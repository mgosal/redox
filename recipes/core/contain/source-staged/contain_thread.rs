use std::sync::{Arc, LockResult, RwLock, RwLockReadGuard};
use std::thread::{self, JoinHandle};

use event::{EventFlags, RawEventQueue};
use libredox::{flag, Fd};
use log::{debug, error, warn};
use redox_scheme::{read_requests, write_responses, Request, SignalBehavior};

use crate::contain_config::ContainConfig;
use crate::filterscheme::FilterScheme;
use crate::{ContainError, ContainResult};

// FFI bindings to relibc namespace API
pub mod ns_ffi {
    extern "C" {
        fn redox_get_ns_v0() -> usize;
        fn redox_mkns_v1(names: *const libc::iovec, num_names: usize, flags: u32) -> usize;
        fn redox_setrens_v1(rns: usize, ens: usize) -> usize;
    }

    const ERROR_BIT: usize = 1 << (usize::BITS - 1);

    fn check(result: usize) -> Result<usize, syscall::Error> {
        if result & ERROR_BIT != 0 {
            Err(syscall::Error::new((result & !ERROR_BIT) as i32))
        } else {
            Ok(result)
        }
    }

    pub fn mkns(scheme_names: &[&str]) -> Result<usize, syscall::Error> {
        let iovecs: Vec<libc::iovec> = scheme_names
            .iter()
            .map(|name| libc::iovec {
                iov_base: name.as_ptr() as *mut _,
                iov_len: name.len(),
            })
            .collect();
        check(unsafe { redox_mkns_v1(iovecs.as_ptr(), iovecs.len(), 0) })
    }

    pub fn getns() -> Result<usize, syscall::Error> {
        check(unsafe { redox_get_ns_v0() })
    }

    pub fn setrens(rns: usize, ens: usize) -> Result<usize, syscall::Error> {
        check(unsafe { redox_setrens_v1(rns, ens) })
    }

    /// call_wo: SYS_CALL with WRITE|FD flags. Sends an FD to a scheme handle.
    /// Reimplemented here because redox_syscall 0.4.1 doesn't have it.
    pub fn call_wo_fd(fd: usize, payload: &[u8]) -> Result<usize, syscall::Error> {
        // CallFlags: WRITE = 1<<9, FD = 1<<11
        const CALL_WRITE: usize = 1 << 9;
        const CALL_FD: usize = 1 << 11;
        let flags = CALL_WRITE | CALL_FD;
        // metadata slice is empty, so len | flags => 0 | flags => flags
        let metadata: &[u64] = &[];
        // SYS_CALL = SYS_CLASS_FILE | SYS_ARG_SLICE | SYS_ARG_MSLICE | 0xCA11
        const SYS_CALL: usize = 0x2000_0000 | 0x0100_0000 | 0x0200_0000 | 0xCA11;
        unsafe {
            syscall::syscall5(
                SYS_CALL,
                fd,
                payload.as_ptr() as usize,
                payload.len(),
                metadata.len() | flags,
                metadata.as_ptr() as usize,
            )
        }
    }
}

pub struct ContainThread {
    config: Arc<RwLock<ContainConfig>>,
    namespace: usize,
    child_pid: usize,
    shutdown_pipe: usize,
    thread_handle: Option<JoinHandle<()>>,
}

impl ContainThread {
    /// Create namespace with FilterScheme for sandbox_schemes.
    ///
    /// Flow:
    /// 1. mkns with pass_schemes only
    /// 2. setrens to new namespace
    /// 3. Get scheme-creation-cap from namespace
    /// 4. Create scheme sockets for each sandbox_scheme via scheme-creation-cap
    /// 5. Register scheme sockets on namespace via IssueRegister + sendfd
    /// 6. Spawn FilterScheme handler thread
    /// 7. Fork child
    /// 8. Child enters namespace via setrens, execs command
    pub fn new(config: ContainConfig) -> ContainResult<Self> {
        let config_arc = Arc::new(RwLock::new(config));
        let config_lock = config_arc.read().map_err(|e| {
            error!("could not get config lock: {}", e);
            ContainError::poison_error(e)
        })?;

        let pass_schemes: Vec<&str> = config_lock
            .pass_schemes
            .iter()
            .map(|s| s.as_str())
            .collect();

        debug!("mkns with pass_schemes: {:?}", pass_schemes);

        // Create namespace with only pass_schemes
        let new_ns = ns_ffi::mkns(&pass_schemes).map_err(|e| {
            error!("could not create namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        debug!("namespace created: {}", new_ns);

        // Enter namespace so Fd::open routes through it
        ns_ffi::setrens(usize::MAX, new_ns).map_err(|e| {
            error!("failed to enter namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        // Get scheme-creation-cap from the namespace
        // This is a kernel-level FD that allows creating scheme handler sockets
        let scheme_cap = Fd::open("namespace:scheme-creation-cap", flag::O_RDONLY, 0).map_err(
            |e| {
                error!("could not get scheme-creation-cap: {}", e);
                ContainError::syscall_error(e)
            },
        )?;
        debug!(
            "got scheme-creation-cap fd={}",
            scheme_cap.raw()
        );

        // For each sandbox_scheme, create a scheme socket via scheme-creation-cap
        // and register it on the namespace
        let mut schemes = Vec::with_capacity(config_lock.sandbox_schemes.len());

        for scheme_name in config_lock.sandbox_schemes.iter() {
            debug!("registering sandbox scheme: {}", scheme_name);

            // Create scheme socket via the kernel scheme-creation-cap
            let scheme_fd = Fd::open(
                &format!(":{}", scheme_name),
                flag::O_CREAT | flag::O_RDWR | flag::O_CLOEXEC,
                0,
            )
            .map_err(|e| {
                error!("could not create scheme socket for {}: {}", scheme_name, e);
                ContainError::syscall_error(e)
            })?;

            debug!(
                "created scheme socket for {}: fd={}",
                scheme_name,
                scheme_fd.raw()
            );

            // Now register this scheme on the namespace via IssueRegister + sendfd
            // Step 1: dup(ns_fd, IssueRegister | name) -> register_cap
            let nsd_issue_register: usize = 2; // NsDup::IssueRegister
            let mut reg_buf = Vec::from(nsd_issue_register.to_ne_bytes());
            reg_buf.extend_from_slice(scheme_name.as_bytes());

            let register_cap = syscall::dup(new_ns, &reg_buf).map_err(|e| {
                error!(
                    "could not issue register cap for {}: {}",
                    scheme_name, e
                );
                ContainError::syscall_error(e)
            })?;

            debug!(
                "got register_cap for {}: fd={}",
                scheme_name, register_cap
            );

            // Step 2: sendfd the scheme socket to the register cap
            let fd_bytes = scheme_fd.raw().to_ne_bytes();
            ns_ffi::call_wo_fd(register_cap, &fd_bytes).map_err(
                |e| {
                    error!(
                        "could not sendfd for scheme {}: {}",
                        scheme_name, e
                    );
                    ContainError::syscall_error(e)
                },
            )?;

            debug!("registered {} on namespace", scheme_name);

            // Close the register cap, we don't need it anymore
            let _ = syscall::close(register_cap);

            let scheme_handler = FilterScheme::new(scheme_name, config_arc.clone());
            schemes.push((scheme_fd, scheme_handler));
        }

        // Refresh namespace FD after registration
        ns_ffi::setrens(
            usize::MAX,
            ns_ffi::getns().map_err(|e| {
                error!("could not get namespace, {}", e);
                ContainError::syscall_error(e)
            })?,
        )
        .map_err(|e| {
            error!("could not update namespace, {}", e);
            ContainError::syscall_error(e)
        })?;

        // Set up event queue for FilterScheme handler thread
        let mut event_queue = RawEventQueue::new().map_err(|e| {
            error!("could not open event queue");
            ContainError::syscall_error(e)
        })?;

        for i in 0..schemes.len() {
            let (scheme_fd, _) = &schemes[i];
            event_queue
                .subscribe(scheme_fd.raw(), i, EventFlags::READ)
                .map_err(|e| {
                    error!(
                        "could not subscribe for event on scheme fd {}, {}",
                        scheme_fd.raw(),
                        e
                    );
                    ContainError::syscall_error(e)
                })?;
        }

        // Shutdown pipe
        let mut pipes = [0i32; 2];
        match unsafe {
            libc::pipe2(
                pipes.as_mut_ptr(),
                syscall::O_CLOEXEC as i32 | syscall::O_NONBLOCK as i32,
            )
        } {
            0 => Ok(()),
            -1 => Err(ContainError::io_error(std::io::Error::last_os_error())),
            _ => unreachable!(),
        }?;

        let [read_pipe, write_pipe] = pipes;
        let read_pipe = read_pipe as usize;
        let write_pipe = write_pipe as usize;
        let pipe_index = schemes.len();

        event_queue
            .subscribe(read_pipe, pipe_index, EventFlags::READ)
            .map_err(|e| {
                error!(
                    "could not subscribe for event on pipe fd {}, {}",
                    read_pipe, e
                );
                ContainError::syscall_error(e)
            })?;

        debug!("pipes [{}, {}], scheme sockets: {}", read_pipe, write_pipe, schemes.len());

        // Sync pipe for parent→child coordination
        let mut sync_pipes = [0i32; 2];
        match unsafe { libc::pipe2(sync_pipes.as_mut_ptr(), 0) } {
            0 => Ok(()),
            -1 => Err(ContainError::io_error(std::io::Error::last_os_error())),
            _ => unreachable!(),
        }?;
        let [sync_read, sync_write] = sync_pipes;

        drop(config_lock);

        // Spawn FilterScheme handler thread BEFORE fork
        let scheme_thread = thread::spawn(move || {
            'events: loop {
                let event = match event_queue.next() {
                    Some(Ok(event)) => {
                        debug!("got event {:?}", event);
                        if event.user_data == pipe_index {
                            debug!("got pipe event, shutting down");
                            break 'events;
                        } else if event.user_data < schemes.len() {
                            event
                        } else {
                            error!("event queue returned unexpected index: {}", event.user_data);
                            break 'events;
                        }
                    }
                    Some(Err(e)) => {
                        error!("event queue returned error {}", e);
                        break 'events;
                    }
                    None => {
                        warn!("event queue returned no data");
                        break 'events;
                    }
                };

                let (scheme_fd, scheme_handler) = &schemes[event.user_data];

                let mut requests = [Request::default()];
                let n_requests = match read_requests(
                    scheme_fd.raw(),
                    &mut requests,
                    SignalBehavior::Restart,
                ) {
                    Ok(0) => {
                        debug!("read socket closing, exiting");
                        break 'events;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        error!("error reading packet from scheme socket: {}", e);
                        break 'events;
                    }
                };

                for i in 0..n_requests {
                    let response = [requests[i].handle_scheme(scheme_handler)];
                    match write_responses(scheme_fd.raw(), &response, SignalBehavior::Restart) {
                        Ok(n) if n == response.len() => {}
                        Ok(n) => {
                            debug!(
                                "did not write response packets, expected {}, got {}",
                                response.len(),
                                n
                            );
                            break 'events;
                        }
                        Err(e) => {
                            error!("error writing response packet: {}", e);
                            break 'events;
                        }
                    };
                }
            }
            debug!("shutdown scheme thread");
        });

        // Fork child
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            let e = std::io::Error::last_os_error();
            error!("contain: fork failed, {}", e);
            return Err(ContainError::io_error(e));
        }

        if pid == 0 {
            // === CHILD ===
            unsafe { libc::close(sync_write); }
            unsafe { libc::close(write_pipe as i32); }

            debug!("child pid={}: waiting for parent", unsafe { libc::getpid() });

            let mut buf = [0u8; 1];
            let n = unsafe { libc::read(sync_read, buf.as_mut_ptr() as *mut _, 1) };
            unsafe { libc::close(sync_read); }

            if n != 1 {
                error!("child: sync read failed (n={})", n);
                std::process::exit(crate::CONTAIN_EXEC_FAIL_EXIT);
            }

            // Child enters namespace
            if let Err(e) = ns_ffi::setrens(usize::MAX, new_ns) {
                error!("child: setrens failed: {}", e);
                std::process::exit(crate::CONTAIN_EXEC_FAIL_EXIT);
            }

            debug!("child: entered namespace {}", new_ns);

            // Verify schemes visible to child
            match std::fs::read_dir("/scheme/") {
                Ok(entries) => {
                    let names: Vec<String> = entries
                        .filter_map(|e| e.ok().and_then(|e| e.file_name().into_string().ok()))
                        .collect();
                    debug!("child: schemes in namespace: {:?}", names);
                }
                Err(e) => error!("child: cannot list /scheme/: {}", e),
            }

            return Ok(Self {
                config: config_arc.clone(),
                namespace: new_ns,
                child_pid: 0,
                shutdown_pipe: 0,
                thread_handle: None,
            });
        }

        // === PARENT ===
        unsafe { libc::close(sync_read); }
        let child_pid = pid as usize;
        debug!("parent: forked child pid={}", child_pid);

        // Signal child to proceed
        let buf = [1u8; 1];
        unsafe { libc::write(sync_write, buf.as_ptr() as *const _, 1); }
        unsafe { libc::close(sync_write); }
        let _ = unsafe { libc::close(read_pipe as i32) };

        Ok(Self {
            config: config_arc,
            namespace: new_ns,
            child_pid,
            shutdown_pipe: write_pipe,
            thread_handle: Some(scheme_thread),
        })
    }

    pub fn namespace(&self) -> usize {
        self.namespace
    }
    pub fn child_pid(&self) -> usize {
        self.child_pid
    }
    pub fn is_child(&self) -> bool {
        self.child_pid == 0
    }

    pub fn config(&self) -> LockResult<RwLockReadGuard<ContainConfig>> {
        self.config.read()
    }

    /// Signal the scheme handler thread to shut down
    pub fn signal_shutdown(&self) {
        let buf = [0u8; 1];
        unsafe {
            libc::write(self.shutdown_pipe as i32, buf.as_ptr() as *const _, 1);
        }
    }
}

impl Drop for ContainThread {
    fn drop(&mut self) {
        debug!("shutdown scheme thread");
        self.signal_shutdown();
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}
