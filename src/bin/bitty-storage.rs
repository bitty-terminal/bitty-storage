//! `bitty-storage` executable component entry point.
//!
//! A bare invocation serves the v1 stdio protocol
//! ([`bitty_storage::component`]) over the host-selected storage root.
//! `--root PATH` selects the root explicitly; without it the component
//! derives `<XDG_STATE_HOME>/bitty/storage` (or
//! `$HOME/.local/state/bitty/storage`) and refuses to run when neither is
//! available. `--version` reports the component version used by the
//! descriptor and release tag, and `--check-manifest` validates a packaged
//! `bitty-component.toml` with the same fail-closed parser the component
//! ships. The binary carries no installer and never publishes itself.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::ExitCode;

use bitty_storage::ceiling::SESSION_APP_DIR_NAME;
use bitty_storage::component::descriptor::{ComponentDescriptor, MAX_DESCRIPTOR_BYTES};
use bitty_storage::component::server::{COMPONENT_VERSION, SERVER_EXIT_INTERNAL, serve_stdio};
use bitty_storage::component::store::StorageRoot;
use bitty_storage::session_codec;

/// Usage refusal (the operator asked for something this binary does not
/// serve); mirrors the other component binaries' `EXIT_REFUSED`.
const EXIT_REFUSED: u8 = 2;

fn usage() {
    eprintln!(
        "usage: bitty-storage [--root PATH] [--version | --check-manifest PATH]\n\
         \n\
         With no arguments (or only --root), serves the storage component\n\
         protocol v1 on stdin/stdout over <root>/<namespace>/. stderr carries\n\
         diagnostics only. Without --root, the root is derived from\n\
         XDG_STATE_HOME (or HOME)."
    );
}

fn check_manifest(path: &std::ffi::OsStr) -> Result<(), String> {
    let file = File::open(path).map_err(|error| format!("cannot open descriptor: {error}"))?;
    let mut bytes = Vec::new();
    file.take((MAX_DESCRIPTOR_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read descriptor: {error}"))?;
    let descriptor = ComponentDescriptor::parse_bytes(&bytes)
        .map_err(|error| format!("invalid descriptor: {error}"))?;
    descriptor
        .validate_for_install()
        .map_err(|error| format!("invalid descriptor: {error}"))?;
    println!(
        "ok {} {} protocol [{}, {}] {}",
        descriptor.name,
        descriptor.version,
        descriptor.protocol_min,
        descriptor.protocol_max,
        descriptor.executable
    );
    Ok(())
}

fn default_root() -> Result<PathBuf, String> {
    let state = session_codec::state_home()
        .ok_or_else(|| "no usable XDG_STATE_HOME or HOME for the storage root".to_owned())?;
    Ok(state.join(SESSION_APP_DIR_NAME).join("storage"))
}

fn serve(root: PathBuf) -> ExitCode {
    match StorageRoot::new(root) {
        Ok(root) => ExitCode::from(serve_stdio(root)),
        Err(error) => {
            eprintln!("bitty-storage: cannot open storage root: {error}");
            ExitCode::from(SERVER_EXIT_INTERNAL)
        }
    }
}

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    match (args.next(), args.next(), args.next()) {
        (None, _, _) => match default_root() {
            Ok(root) => serve(root),
            Err(error) => {
                eprintln!("bitty-storage: {error}");
                ExitCode::from(EXIT_REFUSED)
            }
        },
        (Some(flag), None, _) if flag == "--version" || flag == "-V" => {
            println!("bitty-storage {COMPONENT_VERSION}");
            ExitCode::SUCCESS
        }
        (Some(flag), None, _) if flag == "--help" || flag == "-h" => {
            usage();
            ExitCode::SUCCESS
        }
        (Some(flag), Some(path), None) if flag == "--check-manifest" => {
            match check_manifest(&path) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("bitty-storage: {error}");
                    ExitCode::from(EXIT_REFUSED)
                }
            }
        }
        (Some(flag), Some(path), None) if flag == "--root" => serve(PathBuf::from(path)),
        (Some(flag), None, _) if flag.to_string_lossy().starts_with("--root=") => {
            let value = flag.to_string_lossy();
            let path = value.trim_start_matches("--root=").to_owned();
            if path.is_empty() {
                usage();
                ExitCode::from(EXIT_REFUSED)
            } else {
                serve(PathBuf::from(OsString::from(path)))
            }
        }
        _ => {
            usage();
            ExitCode::from(EXIT_REFUSED)
        }
    }
}
