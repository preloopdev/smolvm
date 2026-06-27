//! Windows-specific platform implementations.
//!
//! Windows support compiles the host control plane; the VM-execution code
//! paths mirror the Linux executor (libkrun on Windows auto-mounts the guest's
//! virtiofs devices, so no mount-wrapper script is needed). Rosetta is a
//! macOS-only feature and is unavailable here.

use crate::error::{Error, Result};
use crate::platform::traits::{RosettaSupport, VmExecutor};
use std::ffi::CString;
use std::path::Path;

/// Windows VM executor implementation.
///
/// Like the Linux executor, this executes the user command directly without a
/// virtiofs mount-wrapper script.
pub struct WindowsExecutor;

impl VmExecutor for WindowsExecutor {
    fn requires_mount_wrapper(&self) -> bool {
        false
    }

    fn build_exec_command(
        &self,
        command: &Option<Vec<String>>,
        _mounts: &[(String, String)],
        _rootfs: &Path,
        _rosetta: bool,
    ) -> Result<(CString, Vec<*const libc::c_char>, Vec<CString>)> {
        let default_cmd = vec!["/bin/sh".to_string()];
        let cmd = command.as_ref().unwrap_or(&default_cmd);

        if cmd.is_empty() {
            return Err(Error::vm_creation("command cannot be empty"));
        }

        let exec_path = CString::new(cmd[0].as_str())
            .map_err(|_| Error::vm_creation("invalid command path"))?;

        let cstrings: Vec<CString> = cmd
            .iter()
            .skip(1)
            .map(|s| CString::new(s.as_str()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::vm_creation("invalid command argument"))?;

        let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
        argv.push(std::ptr::null());

        Ok((exec_path, argv, cstrings))
    }

    fn tool_search_paths(&self) -> &'static [&'static str] {
        &[]
    }

    fn dylib_extension(&self) -> &'static str {
        "dll"
    }

    fn library_search_paths(&self) -> &'static [&'static str] {
        &[]
    }
}

/// Windows Rosetta support (stub - always unavailable).
pub struct WindowsRosetta;

impl RosettaSupport for WindowsRosetta {
    fn is_available(&self) -> bool {
        false
    }

    fn runtime_path(&self) -> Option<&'static str> {
        None
    }
}

/// Get the Rosetta support instance for Windows.
pub fn rosetta_support() -> WindowsRosetta {
    WindowsRosetta
}
