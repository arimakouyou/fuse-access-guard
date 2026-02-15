use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "fuse-access-guard", about = "FUSE-based file access restriction wrapper")]
#[command(trailing_var_arg = true)]
pub struct CliArgs {
    /// Suppress log output to stderr
    #[arg(short, long)]
    pub quiet: bool,

    /// Write access-denied logs to this file
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Executable paths to exclude from access restrictions
    #[arg(long, value_name = "PATH")]
    pub exclude_exec: Vec<String>,

    /// Command and arguments to run under access restrictions
    #[arg(required = true, num_args = 1..)]
    pub command: Vec<String>,
}

impl CliArgs {
    /// Returns the command name (first element after --)
    pub fn command_name(&self) -> &str {
        &self.command[0]
    }

    /// Returns the command arguments (everything after the command name)
    pub fn command_args(&self) -> &[String] {
        &self.command[1..]
    }
}

pub fn parse_args() -> CliArgs {
    CliArgs::parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_command() {
        let args = CliArgs::parse_from(["fuse-access-guard", "--", "ls", "-la"]);
        assert_eq!(args.command_name(), "ls");
        assert_eq!(args.command_args(), &["-la"]);
        assert!(!args.quiet);
        assert!(args.log_file.is_none());
    }

    #[test]
    fn test_parse_with_quiet() {
        let args = CliArgs::parse_from(["fuse-access-guard", "--quiet", "--", "cat", "file.txt"]);
        assert_eq!(args.command_name(), "cat");
        assert_eq!(args.command_args(), &["file.txt"]);
        assert!(args.quiet);
    }

    #[test]
    fn test_parse_with_log_file() {
        let args = CliArgs::parse_from([
            "fuse-access-guard",
            "--log-file",
            "/tmp/access.log",
            "--",
            "bash",
            "-c",
            "echo hello",
        ]);
        assert_eq!(args.log_file, Some(PathBuf::from("/tmp/access.log")));
        assert_eq!(args.command_name(), "bash");
        assert_eq!(args.command_args(), &["-c", "echo hello"]);
    }

    #[test]
    fn test_parse_command_without_separator() {
        let args = CliArgs::parse_from(["fuse-access-guard", "ls", "-la"]);
        assert_eq!(args.command_name(), "ls");
        assert_eq!(args.command_args(), &["-la"]);
    }

    #[test]
    fn test_parse_exclude_exec() {
        let args = CliArgs::parse_from([
            "fuse-access-guard",
            "--exclude-exec",
            "/bin/cat",
            "--exclude-exec",
            "/usr/bin/git",
            "--",
            "ls",
        ]);
        assert_eq!(args.exclude_exec.len(), 2);
        assert_eq!(args.exclude_exec[0], "/bin/cat");
        assert_eq!(args.exclude_exec[1], "/usr/bin/git");
    }
}
