//! Concurrent-save worker for the CTX-0004 two-process test.
//!
//! Usage: `save_worker <destination> <payload-file>`. Reads the payload
//! file and commits it atomically to the destination. Exits 0 on success,
//! 1 on failure. Error text is kinds-only (never payload contents).

use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os().skip(1);
    let (Some(dest), Some(payload)) = (args.next(), args.next()) else {
        eprintln!("usage: save_worker <destination> <payload-file>");
        std::process::exit(2);
    };
    let result = (|| -> Result<(), String> {
        let bytes = std::fs::read(PathBuf::from(&payload)).map_err(|e| e.to_string())?;
        bitty_storage::atomic_io::save_session_bytes(PathBuf::from(&dest).as_path(), &bytes)
            .map_err(|e| e.to_string())
    })();
    if let Err(message) = result {
        eprintln!("save failed: {message}");
        std::process::exit(1);
    }
}
