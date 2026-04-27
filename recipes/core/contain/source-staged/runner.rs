use std::{
    os::unix::process::CommandExt,
    process::{exit, Command},
};

use libredox::call::waitpid;
use log::{debug, error};

use crate::{ContainConfig, ContainError, ContainResult, ContainThread, CONTAIN_EXEC_FAIL_EXIT};

/// Spawn and execute a command with no namespace changes.
pub fn run_not_contained(mut command: Command) -> ContainResult<i32> {
    let mut child = command.spawn().map_err(|e| {
        error!("failed to spawn uncontained command");
        ContainError::io_error(e)
    })?;
    match child
        .wait()
        .map_err(|e| {
            error!("failed to wait on uncontained command");
            ContainError::io_error(e)
        })?
        .code()
    {
        Some(code) => Ok(code),
        None => Ok(1),
    }
}

pub fn run_contained(config: ContainConfig, mut command: Command) -> ContainResult<i32> {
    let config = validate_config(config)?;

    let contain_thread = ContainThread::new(config).map_err(|e| {
        error!("could not create contain thread: {}", e);
        e
    })?;

    if contain_thread.is_child() {
        // === CHILD PATH ===
        debug!("child: executing command {:?}", command);

        let err = command.exec();
        error!("child: failed to exec {:?}: {}", command, err);
        exit(CONTAIN_EXEC_FAIL_EXIT);
    }

    // === PARENT PATH ===
    let child_pid = contain_thread.child_pid();
    debug!("parent: waiting for child pid={}", child_pid);

    let mut status = 0;
    let _ = waitpid(child_pid, &mut status, 0).map_err(|e| {
        error!("waitpid({}) returned error: {}", child_pid, e);
        ContainError::syscall_error(e)
    })?;

    // Reap zombies
    loop {
        let mut c_status = 0;
        let c_pid = waitpid(0, &mut c_status, libc::WNOHANG).unwrap_or_else(|e| {
            error!("waitpid(any) returned error: {}", e);
            0
        });
        if c_pid == 0 {
            break;
        } else {
            debug!("contain: container zombie {}: {:X}", c_pid, c_status);
        }
    }

    debug!(
        "contain: Container {}, pid {}: exit: {:X}",
        contain_thread.namespace(),
        child_pid,
        status
    );

    // Signal scheme handler thread shutdown (also happens in Drop)
    contain_thread.signal_shutdown();

    Ok(status)
}

fn list_schemes() -> ContainResult<Vec<String>> {
    let entries = std::fs::read_dir("/scheme/").map_err(|e| {
        error!("Could not read /scheme/ directory: {}", e);
        ContainError::io_error(e)
    })?;
    let mut schemes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            error!("Could not read scheme entry: {}", e);
            ContainError::io_error(e)
        })?;
        if let Some(name) = entry.file_name().to_str() {
            schemes.push(name.to_string());
        }
    }
    Ok(schemes)
}

fn validate_config(mut config: ContainConfig) -> ContainResult<ContainConfig> {
    let schemes = list_schemes()?;
    debug!("schemes: {:?}", schemes);
    config.pass_schemes.sort();
    config.pass_schemes.dedup();
    config.pass_schemes.retain(|scheme| {
        let is_known = schemes.contains(scheme);
        if !is_known {
            debug!("{scheme} is not recognized");
        }
        is_known
    });
    config.sandbox_schemes.sort();
    config.sandbox_schemes.dedup();
    config.sandbox_schemes.retain(|scheme| {
        let is_known = schemes.contains(scheme);
        if !is_known {
            debug!("{scheme} is not recognized");
        }
        is_known
    });
    if config.root.is_some()
        && !config.sandbox_schemes.iter().any(|scheme| {
            config
                .root
                .as_ref()
                .unwrap()
                .starts_with(&format!("{}:", scheme))
        })
    {
        error!("root {} is not in a sandboxed scheme", config.root.unwrap());
        return Err(ContainError::ConfigError);
    }
    // Add working dir to allowed dirs
    config.files.sort();
    config.files.dedup();
    config.files.retain(|f| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| f.starts_with(&format!("{scheme}:")))
    });
    config.dirs.sort();
    config.dirs.dedup();
    config.dirs.retain(|d| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| d.starts_with(&format!("{scheme}:")))
    });
    config.rofiles.sort();
    config.rofiles.dedup();
    config.rofiles.retain(|f| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| f.starts_with(&format!("{scheme}:")))
    });
    config.rodirs.sort();
    config.rodirs.dedup();
    config.rodirs.retain(|d| {
        config
            .sandbox_schemes
            .iter()
            .any(|scheme| d.starts_with(&format!("{scheme}:")))
    });
    debug!("validated: {:?}", &config);
    Ok(config)
}
