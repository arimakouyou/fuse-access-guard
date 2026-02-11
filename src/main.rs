mod cli;
mod config;
mod logger;
mod namespace;
mod passthrough_fs;
mod rules;

use std::fs::File;
use std::sync::{Arc, Mutex};

fn main() {
    let code = match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("fuse-access-guard: error: {e}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args = cli::parse_args();

    // Load settings from .claude/settings.json in cwd
    let cwd = std::env::current_dir()?;
    let settings = config::load_settings(&cwd)?;

    // Build access rules
    let rules = rules::AccessRules::from_settings(&settings, &cwd)?;
    let rules = Arc::new(rules);

    // Set up logger
    let log_file = match &args.log_file {
        Some(path) => Some(File::create(path)?),
        None => None,
    };
    let logger = logger::Logger::new(args.quiet, log_file);
    let logger = Arc::new(Mutex::new(logger));

    // Compute mount points from deny rules
    let mount_points = namespace::compute_mount_points(&rules);
    // Build namespace config
    let ns_config = namespace::NamespaceConfig {
        mount_points,
        command: args.command_name().to_string(),
        args: args.command_args().iter().map(|s| s.to_string()).collect(),
    };

    // Run in namespace
    let exit_code = namespace::run_in_namespace(ns_config, rules, logger)?;
    Ok(exit_code)
}
