//! FFI Bridge - Safe foreign function interface for unprivileged runtimes
//!
//! This module provides C-compatible FFI bindings for Lua, JS, Kotlin, and Mojo
//! to call eval_aln_envelope safely without exposing internal Rust types.

use crate::eval_aln_envelope;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

/// FFI entrypoint for C-compatible runtimes
///
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers.
/// Callers must ensure `input` is a valid null-terminated C string.
///
/// # Arguments
///
/// * `input` - Pointer to null-terminated JSON bytes
/// * `input_len` - Length of input in bytes
/// * `output_len` - Pointer to store output length
///
/// # Returns
///
/// * Pointer to null-terminated JSON result (caller must free)
#[no_mangle]
pub unsafe extern "C" fn aln_eval_envelope_ffi(
    input: *const c_char,
    input_len: usize,
    output_len: *mut usize,
) -> *mut c_char {
    if input.is_null() || output_len.is_null() {
        return ptr::null_mut();
    }

    // Read input bytes
    let input_bytes = std::slice::from_raw_parts(input as *const u8, input_len);
    
    // Evaluate envelope
    let result = eval_aln_envelope(input_bytes);
    
    // Set output length
    *output_len = result.len();
    
    // Convert to C string
    match CString::new(result) {
        Ok(c_string) => c_string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free memory allocated by FFI functions
///
/// # Safety
///
/// This function is unsafe because it takes ownership of a raw pointer.
/// Callers must ensure `ptr` was allocated by this library.
#[no_mangle]
pub unsafe extern "C" fn aln_free_ffi_result(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_ffi_bridge_valid_input() {
        let input = CString::new(r#"{"kind":"SourzePolicy","payload":{}}"#).unwrap();
        let mut output_len: usize = 0;
        
        unsafe {
            let result = aln_eval_envelope_ffi(
                input.as_ptr(),
                input.as_bytes().len(),
                &mut output_len,
            );
            
            assert!(!result.is_null());
            assert!(output_len > 0);
            
            // Clean up
            aln_free_ffi_result(result);
        }
    }
}
