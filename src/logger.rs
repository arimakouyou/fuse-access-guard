use std::fs::File;
use std::io::Write;
use std::time::SystemTime;

use crate::rules::Operation;

pub struct Logger {
    quiet: bool,
    log_file: Option<File>,
}

impl Logger {
    pub fn new(quiet: bool, log_file: Option<File>) -> Self {
        Logger { quiet, log_file }
    }

    pub fn log_denied(&mut self, pid: u32, process_name: &str, path: &str, op: Operation) {
        let timestamp = humanize_timestamp(SystemTime::now());
        let op_str = match op {
            Operation::Read => "read",
            Operation::Write => "write",
            Operation::Execute => "execute",
        };
        let line = format!(
            "[DENIED] {timestamp} pid={pid} proc={process_name} op={op_str} path={path}\n"
        );

        if !self.quiet {
            eprint!("{line}");
        }

        if let Some(ref mut f) = self.log_file {
            let _ = f.write_all(line.as_bytes());
        }
    }
}

fn humanize_timestamp(time: SystemTime) -> String {
    let dur = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Simple UTC timestamp: YYYY-MM-DDTHH:MM:SSZ
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate date from days since epoch (1970-01-01)
    let (year, month, day) = days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as IoRead;

    #[test]
    fn test_log_format() {
        let mut buf = Vec::new();
        {
            let file = tempfile::tempfile().unwrap();
            let mut logger = Logger::new(true, Some(file));
            logger.log_denied(1234, "cat", "/home/user/.env", Operation::Read);
            // Read back from the file
            let file = logger.log_file.as_mut().unwrap();
            file.flush().unwrap();
            use std::io::Seek;
            file.seek(std::io::SeekFrom::Start(0)).unwrap();
            file.read_to_end(&mut buf).unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("[DENIED] "));
        assert!(output.contains("pid=1234"));
        assert!(output.contains("proc=cat"));
        assert!(output.contains("op=read"));
        assert!(output.contains("path=/home/user/.env"));
    }

    #[test]
    fn test_quiet_suppresses_stderr() {
        // quiet=true should not panic or error
        let mut logger = Logger::new(true, None);
        logger.log_denied(1, "test", "/tmp/file", Operation::Write);
    }

    #[test]
    fn test_file_output() {
        let file = tempfile::tempfile().unwrap();
        let mut logger = Logger::new(true, Some(file));
        logger.log_denied(42, "bash", "/etc/shadow", Operation::Read);

        let file = logger.log_file.as_mut().unwrap();
        file.flush().unwrap();
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert!(content.contains("[DENIED]"));
        assert!(content.contains("pid=42"));
    }

    #[test]
    fn test_timestamp_format() {
        let ts = humanize_timestamp(SystemTime::UNIX_EPOCH);
        assert_eq!(ts, "1970-01-01T00:00:00Z");
    }
}
