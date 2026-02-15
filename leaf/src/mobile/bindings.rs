#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]
#![allow(clippy::all)]

#[cfg(target_os = "android")]
pub const android_LogPriority_ANDROID_LOG_VERBOSE: i32 = 2;

#[cfg(target_os = "android")]
unsafe extern "C" {
    pub fn __android_log_write(
        prio: std::os::raw::c_int,
        tag: *const std::os::raw::c_char,
        text: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
include!(concat!(env!("OUT_DIR"), "/mobile_bindings.rs"));
