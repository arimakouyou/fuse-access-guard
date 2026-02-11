use std::collections::HashSet;
use std::ffi::CString;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use crate::logger::Logger;
use crate::passthrough_fs::PassthroughFs;
use crate::rules::AccessRules;

#[derive(Debug)]
pub struct MountPoint {
    pub source: PathBuf,
    pub target: PathBuf,
}

pub struct NamespaceConfig {
    pub mount_points: Vec<MountPoint>,
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum NamespaceError {
    #[error("failed to fork: {0}")]
    ForkError(#[from] nix::Error),
    #[error("failed to execute command: {0}")]
    ExecError(String),
}

/// Compute mount points from deny rules.
/// Groups deny-rule paths by their parent directory to minimize mounts.
pub fn compute_mount_points(rules: &AccessRules) -> Vec<MountPoint> {
    let dirs: HashSet<PathBuf> = rules
        .denied_paths()
        .iter()
        .filter_map(|p| p.parent().map(|d| d.to_path_buf()))
        .collect();

    dirs.into_iter()
        .map(|d| MountPoint {
            source: d.clone(),
            target: d,
        })
        .collect()
}

/// Run a command inside a mount namespace with FUSE access guards.
///
/// Process model (double fork):
/// 1. fork() -> child A (FUSE daemon)
/// 2. Child A: unshare(CLONE_NEWUSER | CLONE_NEWNS) -> uid/gid maps -> mount private
///    -> fork() -> child B (command runner)
///    -> mount FUSE (background sessions)
///    -> signal child B via pipe -> waitpid(child B) -> cleanup
/// 3. Child B: wait for pipe signal -> execvp(command)
/// 4. Parent: waitpid(child A) -> propagate exit code
pub fn run_in_namespace(
    config: NamespaceConfig,
    rules: Arc<AccessRules>,
    logger: Arc<Mutex<Logger>>,
) -> Result<i32, NamespaceError> {
    if config.mount_points.is_empty() {
        return run_command_directly(&config.command, &config.args);
    }

    match unsafe { fork() }? {
        ForkResult::Child => {
            fuse_daemon_process(&config, &rules, &logger);
            std::process::exit(127);
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).map_err(NamespaceError::ForkError)?;
            match status {
                WaitStatus::Exited(_, code) => Ok(code),
                WaitStatus::Signaled(_, sig, _) => Ok(128 + sig as i32),
                _ => Ok(1),
            }
        }
    }
}

/// Child A: sets up namespace, forks child B FIRST, mounts FUSE, signals child B.
fn fuse_daemon_process(
    config: &NamespaceConfig,
    rules: &Arc<AccessRules>,
    logger: &Arc<Mutex<Logger>>,
) {
    // Save uid/gid before entering user namespace
    let uid = nix::unistd::getuid();
    let gid = nix::unistd::getgid();

    // 1. Create user + mount namespace
    if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS) {
        eprintln!(
            "fuse-access-guard: failed to create namespace: {e}\n\
             Hint: ensure your kernel supports user namespaces \
             (sysctl kernel.unprivileged_userns_clone=1)"
        );
        std::process::exit(126);
    }

    // 2. Write uid/gid mappings
    if let Err(e) = write_id_mappings(uid.as_raw(), gid.as_raw()) {
        eprintln!("fuse-access-guard: failed to set up uid/gid mappings: {e}");
        std::process::exit(126);
    }

    // 3. Make mount propagation private
    if let Err(e) = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    ) {
        eprintln!("fuse-access-guard: failed to set mount propagation to private: {e}");
        std::process::exit(126);
    }

    // 4. Create a pipe for synchronization: child B waits until FUSE is mounted
    let (pipe_read, pipe_write) = nix::unistd::pipe().unwrap_or_else(|e| {
        eprintln!("fuse-access-guard: failed to create pipe: {e}");
        std::process::exit(126);
    });

    // 5. Fork BEFORE spawning FUSE threads (fork after threads is unsafe)
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            // Child B (grandchild): wait for FUSE mount signal, then exec
            drop(pipe_write);
            // Block until parent writes to pipe (signals FUSE is ready)
            let mut buf = [0u8; 1];
            let mut reader = std::fs::File::from(pipe_read);
            let _ = reader.read(&mut buf);
            // Force cwd re-resolution through the new FUSE mount.
            // After fork, the kernel caches the pre-mount dentry for cwd.
            // We must chdir away and back to force re-resolution through VFS.
            if let Ok(cwd) = std::env::current_dir() {
                let _ = std::env::set_current_dir("/");
                let _ = std::env::set_current_dir(&cwd);
            }
            exec_command(&config.command, &config.args);
        }
        Ok(ForkResult::Parent { child: grandchild }) => {
            drop(pipe_read);

            // 6. Open source directories BEFORE mounting FUSE (to bypass FUSE mount)
            let mut source_fds = Vec::new();
            for mp in &config.mount_points {
                match std::fs::File::open(&mp.source) {
                    Ok(fd) => source_fds.push((mp, fd)),
                    Err(e) => {
                        eprintln!(
                            "fuse-access-guard: failed to open source dir {}: {e}",
                            mp.source.display()
                        );
                        let _ = nix::unistd::write(&pipe_write, b"x");
                        let _ = nix::sys::signal::kill(grandchild, nix::sys::signal::SIGTERM);
                        let _ = waitpid(grandchild, None);
                        std::process::exit(126);
                    }
                }
            }

            // 7. Mount FUSE AFTER forking (so FUSE threads only exist in this process)
            let mut sessions = Vec::new();
            for (mp, source_fd) in source_fds {
                let fs = PassthroughFs::new(
                    mp.source.clone(),
                    source_fd,
                    Arc::clone(rules),
                    Arc::clone(logger),
                );
                let options = vec![
                    fuser::MountOption::FSName("fuse-access-guard".to_string()),
                    fuser::MountOption::DefaultPermissions,
                ];
                match fuser::spawn_mount2(fs, &mp.target, &options) {
                    Ok(session) => sessions.push(session),
                    Err(e) => {
                        eprintln!(
                            "fuse-access-guard: FUSE mount failed on {}: {e}\n\
                             Hint: ensure fuse3 is installed (apt install fuse3 libfuse3-dev)",
                            mp.target.display()
                        );
                        // Signal grandchild to exit, then cleanup
                        let _ = nix::unistd::write(&pipe_write, b"x");
                        let _ = nix::sys::signal::kill(grandchild, nix::sys::signal::SIGTERM);
                        let _ = waitpid(grandchild, None);
                        std::process::exit(126);
                    }
                }
            }

            // 8. Signal grandchild that FUSE is ready
            let _ = nix::unistd::write(&pipe_write, b"r");
            drop(pipe_write);

            // 8. Wait for grandchild to exit
            let exit_code = wait_for_child(grandchild);

            // 9. Drop sessions to unmount FUSE
            drop(sessions);
            std::process::exit(exit_code);
        }
        Err(e) => {
            eprintln!("fuse-access-guard: second fork failed: {e}");
            std::process::exit(126);
        }
    }
}

fn write_id_mappings(uid: u32, gid: u32) -> std::io::Result<()> {
    std::fs::write("/proc/self/setgroups", "deny")?;
    let uid_map = format!("{uid} {uid} 1\n");
    let gid_map = format!("{gid} {gid} 1\n");
    std::fs::write("/proc/self/uid_map", uid_map)?;
    std::fs::write("/proc/self/gid_map", gid_map)?;
    Ok(())
}

fn exec_command(command: &str, args: &[String]) {
    let cmd = CString::new(command).unwrap_or_else(|_| {
        eprintln!("fuse-access-guard: invalid command name");
        std::process::exit(127);
    });

    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(cmd.clone());
    for arg in args {
        c_args.push(CString::new(arg.as_str()).unwrap_or_else(|_| {
            eprintln!("fuse-access-guard: invalid argument: {arg}");
            std::process::exit(127);
        }));
    }

    let Err(e) = nix::unistd::execvp(&cmd, &c_args);
    eprintln!("fuse-access-guard: failed to execute '{command}': {e}");
    std::process::exit(127);
}

fn wait_for_child(child: Pid) -> i32 {
    match waitpid(child, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        Ok(WaitStatus::Signaled(_, sig, _)) => 128 + sig as i32,
        _ => 1,
    }
}

fn run_command_directly(command: &str, args: &[String]) -> Result<i32, NamespaceError> {
    let status = std::process::Command::new(command)
        .args(args)
        .status()
        .map_err(|e| NamespaceError::ExecError(format!("{command}: {e}")))?;

    Ok(status.code().unwrap_or(1))
}
