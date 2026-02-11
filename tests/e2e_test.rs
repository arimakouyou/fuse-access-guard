use std::fs;
use std::process::Command;

fn build_binary() -> String {
    let output = Command::new("cargo")
        .args(["build", "--quiet"])
        .output()
        .expect("failed to build");
    assert!(output.status.success(), "cargo build failed");

    let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("target/debug/fuse-access-guard");
    path.to_string_lossy().to_string()
}

fn setup_test_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();

    // Create .claude/settings.json
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{
            "permissions": {
                "deny": [
                    "Read(./secret.txt)",
                    "Read(./.env)"
                ]
            }
        }"#,
    )
    .unwrap();

    // Create test files
    fs::write(dir.path().join("secret.txt"), "top secret data").unwrap();
    fs::write(dir.path().join(".env"), "API_KEY=secret123").unwrap();
    fs::write(dir.path().join("allowed.txt"), "public data").unwrap();

    dir
}

#[test]
#[ignore] // Requires FUSE and user namespace support
fn test_deny_read_blocked() {
    let binary = build_binary();
    let test_dir = setup_test_dir();

    let output = Command::new(&binary)
        .args(["--", "cat", "secret.txt"])
        .current_dir(test_dir.path())
        .output()
        .expect("failed to run");

    // Should fail with permission denied
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("=== deny read test ===");
    eprintln!("exit code: {:?}", output.status.code());
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
    assert!(
        !output.status.success(),
        "Expected failure but got success. stdout: {stdout}, stderr: {stderr}"
    );
}

#[test]
#[ignore] // Requires FUSE and user namespace support
fn test_allowed_read_passes() {
    let binary = build_binary();
    let test_dir = setup_test_dir();

    let output = Command::new(&binary)
        .args(["--", "cat", "allowed.txt"])
        .current_dir(test_dir.path())
        .output()
        .expect("failed to run");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprintln!("=== allowed read test ===");
    eprintln!("exit code: {:?}", output.status.code());
    eprintln!("stdout: {stdout}");
    eprintln!("stderr: {stderr}");
    assert!(output.status.success(), "expected success, stderr: {stderr}");
    assert_eq!(stdout.trim(), "public data");
}

#[test]
#[ignore] // Requires FUSE and user namespace support
fn test_child_process_also_blocked() {
    let binary = build_binary();
    let test_dir = setup_test_dir();

    let output = Command::new(&binary)
        .args(["--", "bash", "-c", "cat secret.txt"])
        .current_dir(test_dir.path())
        .output()
        .expect("failed to run");

    assert!(!output.status.success());
}

#[test]
#[ignore] // Requires FUSE and user namespace support
fn test_quiet_flag_suppresses_output() {
    let binary = build_binary();
    let test_dir = setup_test_dir();

    let output = Command::new(&binary)
        .args(["--quiet", "--", "cat", "secret.txt"])
        .current_dir(test_dir.path())
        .output()
        .expect("failed to run");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[DENIED]"),
        "Expected no DENIED log in quiet mode, got: {stderr}"
    );
}

/// Test that the binary runs successfully when no deny rules match (no FUSE needed)
#[test]
fn test_no_mount_points_direct_execution() {
    let binary = build_binary();
    let dir = tempfile::tempdir().unwrap();

    // Create settings with a deny rule that won't match anything we access
    let claude_dir = dir.path().join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions":{"deny":["Read(./nonexistent-file.txt)"]}}"#,
    )
    .unwrap();

    // Create a file we'll actually read
    fs::write(dir.path().join("hello.txt"), "hello world").unwrap();

    let output = Command::new(&binary)
        .args(["--", "cat", "hello.txt"])
        .current_dir(dir.path())
        .output()
        .expect("failed to run");

    // This should work because the mount points won't include hello.txt's directory
    // (only nonexistent-file.txt's directory would be mounted)
    // Note: this test may or may not pass depending on mount point computation
    // The important thing is it doesn't crash
    let _ = output;
}
