#![allow(clippy::missing_safety_doc)]
use std::{
    ffi::{CStr, CString},
    os::raw::c_char,
};

#[cfg(target_os = "android")]
use jni::objects::{GlobalRef, JClass, JString};
#[cfg(target_os = "android")]
use jni::sys::{jboolean, jint, JNI_VERSION_1_6};
#[cfg(target_os = "android")]
use jni::{JNIEnv, JavaVM};

/// No error.
pub const ERR_OK: i32 = 0;
/// Config path error.
pub const ERR_CONFIG_PATH: i32 = 1;
/// Config parsing error.
pub const ERR_CONFIG: i32 = 2;
/// IO error.
pub const ERR_IO: i32 = 3;
/// Config file watcher error.
pub const ERR_WATCHER: i32 = 4;
/// Async channel send error.
pub const ERR_ASYNC_CHANNEL_SEND: i32 = 5;
/// Sync channel receive error.
pub const ERR_SYNC_CHANNEL_RECV: i32 = 6;
/// Runtime manager error.
pub const ERR_RUNTIME_MANAGER: i32 = 7;
/// No associated config file.
pub const ERR_NO_CONFIG_FILE: i32 = 8;
/// No data found.
pub const ERR_NO_DATA: i32 = 9;

fn to_errno(e: leaf::Error) -> i32 {
    match e {
        leaf::Error::Config(..) => ERR_CONFIG,
        leaf::Error::NoConfigFile => ERR_NO_CONFIG_FILE,
        leaf::Error::Io(..) => ERR_IO,
        #[cfg(feature = "auto-reload")]
        leaf::Error::Watcher(..) => ERR_WATCHER,
        leaf::Error::AsyncChannelSend(..) => ERR_ASYNC_CHANNEL_SEND,
        leaf::Error::SyncChannelRecv(..) => ERR_SYNC_CHANNEL_RECV,
        leaf::Error::RuntimeManager => ERR_RUNTIME_MANAGER,
    }
}

/// Starts leaf with options, on a successful start this function blocks the current
/// thread.
///
/// @note This is not a stable API, parameters will change from time to time.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @param auto_reload Enabls auto reloading when config file changes are detected,
///                    takes effect only when the "auto-reload" feature is enabled.
/// @param multi_thread Whether to use a multi-threaded runtime.
/// @param auto_threads Sets the number of runtime worker threads automatically,
///                     takes effect only when multi_thread is true.
/// @param threads Sets the number of runtime worker threads, takes effect when
///                     multi_thread is true, but can be overridden by auto_threads.
/// @param stack_size Sets stack size of the runtime worker threads, takes effect when
///                   multi_thread is true.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
#[allow(unused_variables)]
pub unsafe extern "C" fn leaf_run_with_options(
    rt_id: u16,
    config_path: *const c_char,
    auto_reload: bool, // requires this parameter anyway
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::util::run_with_options(
            rt_id,
            config_path.to_string(),
            #[cfg(feature = "auto-reload")]
            auto_reload,
            multi_thread,
            auto_threads,
            threads as usize,
            stack_size as usize,
        ) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Starts leaf with a single-threaded runtime, on a successful start this function
/// blocks the current thread.
///
/// @param rt_id A unique ID to associate this leaf instance, this is required when
///              calling subsequent FFI functions, e.g. reload, shutdown.
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return ERR_OK on finish running, any other errors means a startup failure.
#[no_mangle]
pub unsafe extern "C" fn leaf_run(rt_id: u16, config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::File(config_path.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

#[no_mangle]
pub unsafe extern "C" fn leaf_run_with_config_string(rt_id: u16, config: *const c_char) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::Str(config.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: leaf::RuntimeOption::SingleThread,
        };
        if let Err(e) = leaf::start(rt_id, opts) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Reloads DNS servers, outbounds and routing rules from the config file.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns ERR_OK on success.
#[no_mangle]
pub extern "C" fn leaf_reload(rt_id: u16) -> i32 {
    if let Err(e) = leaf::reload(rt_id) {
        return to_errno(e);
    }
    ERR_OK
}

/// Shuts down leaf.
///
/// @param rt_id The ID of the leaf instance to reload.
///
/// @return Returns true on success, false otherwise.
#[no_mangle]
pub extern "C" fn leaf_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

/// Tests the configuration.
///
/// @param config_path The path of the config file, must be a file with suffix .conf
///                    or .json, according to the enabled features.
/// @return Returns ERR_OK on success, i.e no syntax error.
#[no_mangle]
pub unsafe extern "C" fn leaf_test_config(config_path: *const c_char) -> i32 {
    if let Ok(config_path) = unsafe { CStr::from_ptr(config_path).to_str() } {
        if let Err(e) = leaf::test_config(config_path) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
}

/// Runs a health check for an outbound.
///
/// This performs an active health check by sending a PING to healthcheck.leaf
/// and waiting for a PONG response through the specified outbound, testing both
/// TCP and UDP protocols.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound to test.
/// @param timeout_ms Timeout in milliseconds (0 for default 4 seconds).
/// @return Returns ERR_OK if either TCP or UDP health check succeeds, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_health_check(
    rt_id: u16,
    outbound_tag: *const c_char,
    timeout_ms: u64,
) -> i32 {
    use std::time::Duration;

    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        rt.block_on(async move { m.health_check_outbound(&outbound_tag, timeout).await })
    } else {
        Err(leaf::Error::RuntimeManager)
    };

    match result {
        Ok((tcp_res, udp_res)) => {
            if tcp_res.is_ok() || udp_res.is_ok() {
                ERR_OK
            } else {
                ERR_IO
            }
        }
        Err(e) => to_errno(e),
    }
}

/// Gets the last active time for an outbound.
///
/// This returns the timestamp of the last successful connection through the outbound.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound.
/// @param timestamp_s Pointer to store the timestamp in seconds since epoch.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_get_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    timestamp_s: *mut u32,
) -> i32 {
    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { m.get_outbound_last_peer_active(&outbound_tag).await })
    } else {
        return to_errno(leaf::Error::RuntimeManager);
    };

    match result {
        Ok(Some(ts)) => {
            unsafe { *timestamp_s = ts };
            ERR_OK
        }
        Ok(None) => ERR_NO_DATA,
        Err(e) => to_errno(e),
    }
}

/// Gets seconds since last active time for an outbound.
///
/// This returns the number of seconds elapsed since the last successful
/// connection through the specified outbound.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound.
/// @param since_s Pointer to store the seconds since last active.
/// @return Returns ERR_OK on success, ERR_NO_DATA if no active time found, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_get_since_last_active(
    rt_id: u16,
    outbound_tag: *const c_char,
    since_s: *mut u32,
) -> i32 {
    let outbound_tag = if let Ok(tag) = unsafe { CStr::from_ptr(outbound_tag).to_str() } {
        tag.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move { m.get_outbound_last_peer_active(&outbound_tag).await })
    } else {
        return to_errno(leaf::Error::RuntimeManager);
    };

    match result {
        Ok(Some(ts)) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .unwrap_or(0);
            let since = now.saturating_sub(ts);
            unsafe { *since_s = since };
            ERR_OK
        }
        Ok(None) => ERR_NO_DATA,
        Err(e) => to_errno(e),
    }
}

// ---------------------------------------------------------------------------
// Helper: write a Rust string into a caller-supplied C buffer.
// Returns the number of bytes written (excluding NUL) on success,
// or -(required_size) if the buffer is too small.
// ---------------------------------------------------------------------------
unsafe fn write_to_buf(s: &str, buf: *mut c_char, buf_len: i32) -> i32 {
    let needed = s.len() as i32 + 1; // +1 for NUL
    if buf.is_null() || buf_len < needed {
        return -needed;
    }
    std::ptr::copy_nonoverlapping(s.as_ptr(), buf as *mut u8, s.len());
    *buf.add(s.len()) = 0; // NUL terminator
    s.len() as i32
}

/// Sets the selected outbound for a selector group.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound The tag of the selector outbound (e.g. "proxy").
/// @param select The tag of the outbound to select.
/// @return ERR_OK on success, error code otherwise.
#[cfg(feature = "outbound-select")]
#[no_mangle]
pub unsafe extern "C" fn leaf_set_outbound_selected(
    rt_id: u16,
    outbound: *const c_char,
    select: *const c_char,
) -> i32 {
    let outbound = match CStr::from_ptr(outbound).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_CONFIG_PATH,
    };
    let select = match CStr::from_ptr(select).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_CONFIG_PATH,
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(async { m.set_outbound_selected(&outbound, &select).await }) {
            Ok(()) => ERR_OK,
            Err(e) => to_errno(e),
        }
    } else {
        ERR_RUNTIME_MANAGER
    }
}

/// Gets the currently selected outbound tag for a selector group.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound The tag of the selector outbound (e.g. "proxy").
/// @param buf Buffer to receive the selected tag as a NUL-terminated UTF-8 string.
/// @param buf_len Size of the buffer in bytes.
/// @return Number of bytes written (excluding NUL) on success,
///         negative value -(required_size) if buffer too small,
///         or error code on failure.
#[cfg(feature = "outbound-select")]
#[no_mangle]
pub unsafe extern "C" fn leaf_get_outbound_selected(
    rt_id: u16,
    outbound: *const c_char,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    let outbound = match CStr::from_ptr(outbound).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_CONFIG_PATH,
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(async { m.get_outbound_selected(&outbound).await }) {
            Ok(selected) => write_to_buf(&selected, buf, buf_len),
            Err(e) => to_errno(e),
        }
    } else {
        ERR_RUNTIME_MANAGER
    }
}

/// Gets the list of available outbound tags for a selector group as a JSON array.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound The tag of the selector outbound (e.g. "proxy").
/// @param buf Buffer to receive a JSON array string, e.g. `["node1","node2"]`.
/// @param buf_len Size of the buffer in bytes.
/// @return Number of bytes written (excluding NUL) on success,
///         negative value -(required_size) if buffer too small,
///         or error code on failure.
#[cfg(feature = "outbound-select")]
#[no_mangle]
pub unsafe extern "C" fn leaf_get_outbound_selects(
    rt_id: u16,
    outbound: *const c_char,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    let outbound = match CStr::from_ptr(outbound).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_CONFIG_PATH,
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(async { m.get_outbound_selects(&outbound).await }) {
            Ok(tags) => {
                let json = serde_json::to_string(&tags).unwrap_or_else(|_| "[]".to_string());
                write_to_buf(&json, buf, buf_len)
            }
            Err(e) => to_errno(e),
        }
    } else {
        ERR_RUNTIME_MANAGER
    }
}

/// Runs a health check and returns TCP latency in milliseconds.
///
/// Unlike `leaf_health_check` which only returns OK/fail, this function
/// returns the actual TCP latency measurement.
///
/// @param rt_id The ID of the leaf instance.
/// @param outbound_tag The tag of the outbound to test.
/// @param timeout_ms Timeout in milliseconds (0 for default 4 seconds).
/// @param tcp_ms Pointer to store TCP latency in ms. Set to 0 if TCP check fails.
/// @param udp_ms Pointer to store UDP latency in ms. Set to 0 if UDP check fails.
/// @return ERR_OK if at least one check succeeds, error code otherwise.
#[no_mangle]
pub unsafe extern "C" fn leaf_health_check_with_latency(
    rt_id: u16,
    outbound_tag: *const c_char,
    timeout_ms: u64,
    tcp_ms: *mut u64,
    udp_ms: *mut u64,
) -> i32 {
    use std::time::Duration;

    let outbound_tag = match CStr::from_ptr(outbound_tag).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return ERR_CONFIG_PATH,
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        rt.block_on(async move { m.health_check_outbound(&outbound_tag, timeout).await })
    } else {
        return ERR_RUNTIME_MANAGER;
    };

    match result {
        Ok((tcp_res, udp_res)) => {
            let tcp_ok = tcp_res.is_ok();
            let udp_ok = udp_res.is_ok();
            if !tcp_ms.is_null() {
                *tcp_ms = tcp_res.ok().map(|d| d.as_millis() as u64).unwrap_or(0);
            }
            if !udp_ms.is_null() {
                *udp_ms = udp_res.ok().map(|d| d.as_millis() as u64).unwrap_or(0);
            }
            if tcp_ok || udp_ok {
                ERR_OK
            } else {
                ERR_IO
            }
        }
        Err(e) => to_errno(e),
    }
}

/// Gets connection statistics as a JSON array.
///
/// Returns a JSON array of objects with fields:
/// `network`, `inbound_tag`, `source`, `destination`, `outbound_tag`,
/// `bytes_sent`, `bytes_recvd`, `send_completed`, `recv_completed`.
///
/// @param rt_id The ID of the leaf instance.
/// @param buf Buffer to receive the JSON string.
/// @param buf_len Size of the buffer in bytes.
/// @return Number of bytes written (excluding NUL) on success,
///         negative value -(required_size) if buffer too small,
///         or error code on failure.
#[no_mangle]
pub unsafe extern "C" fn leaf_get_stats(
    rt_id: u16,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    #[derive(serde::Serialize)]
    struct Stat {
        network: String,
        inbound_tag: String,
        source: String,
        destination: String,
        outbound_tag: String,
        bytes_sent: u64,
        bytes_recvd: u64,
        send_completed: bool,
        recv_completed: bool,
    }

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    if let Some(m) = manager {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let json = rt.block_on(async {
            let sm = m.stat_manager();
            let sm = sm.read().await;
            let stats: Vec<Stat> = sm
                .counters
                .iter()
                .map(|c| Stat {
                    network: c.sess.network.to_string(),
                    inbound_tag: c.sess.inbound_tag.clone(),
                    source: c.sess.source.to_string(),
                    destination: c.sess.destination.to_string(),
                    outbound_tag: c.sess.outbound_tag.clone(),
                    bytes_sent: c.bytes_sent(),
                    bytes_recvd: c.bytes_recvd(),
                    send_completed: c.send_completed(),
                    recv_completed: c.recv_completed(),
                })
                .collect();
            serde_json::to_string(&stats).unwrap_or_else(|_| "[]".to_string())
        });
        write_to_buf(&json, buf, buf_len)
    } else {
        ERR_RUNTIME_MANAGER
    }
}

/// Sets a process environment variable visible to the leaf runtime.
///
/// Must be called BEFORE leaf_run* — leaf reads ASSET_LOCATION lazily on
/// first access (lazy_static) and caches it for the process lifetime.
///
/// Primary use: set ASSET_LOCATION so leaf can find geo.mmdb for GeoIP rules.
///
/// @param key   NUL-terminated UTF-8 env var name  (e.g. "ASSET_LOCATION").
/// @param value NUL-terminated UTF-8 env var value (e.g. "/data/data/com.app/files/leaf").
#[no_mangle]
pub unsafe extern "C" fn leaf_set_env(key: *const c_char, value: *const c_char) {
    if let (Ok(k), Ok(v)) = (
        CStr::from_ptr(key).to_str(),
        CStr::from_ptr(value).to_str(),
    ) {
        std::env::set_var(k, v);
    }
}

/// Frees a C string that was allocated by leaf FFI functions.
/// Currently unused but reserved for future use if we switch to
/// returning allocated strings.
#[no_mangle]
pub unsafe extern "C" fn leaf_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

// ===========================================================================
// Android JNI entry points
// ===========================================================================

/// Called automatically when the native library is loaded on Android.
/// Stores the Java VM reference for later JNI callbacks.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _: *mut std::os::raw::c_void) -> jint {
    leaf::mobile::callback::android::set_jvm(vm);
    JNI_VERSION_1_6
}

/// Called when the native library is unloaded.
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "system" fn JNI_OnUnload(_vm: JavaVM, _: *mut std::os::raw::c_void) {
    leaf::mobile::callback::android::unset_protect_socket_callback();
    leaf::mobile::callback::android::unset_jvm();
}

/// JNI: Register the socket protection callback.
/// Called from LeafBridge.nativeSetProtectSocketCallback() in Kotlin.
///
/// This tells leaf to call LeafBridge.protectSocket(fd) whenever it creates
/// a socket that needs VPN protection (to avoid routing loops).
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn Java_com_follow_clash_core_LeafBridge_nativeSetProtectSocketCallback(
    mut env: JNIEnv,
    class: JClass,
) {
    // Register "protectSocket" static method with signature (I)Z
    if let Ok(class_g) = env.new_global_ref(class) {
        leaf::mobile::callback::android::set_protect_socket_callback(
            class_g,
            "protectSocket".to_string(),
        );
    }
}

/// JNI: Start leaf with options. Blocks the calling thread.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn Java_com_follow_clash_core_LeafBridge_leafRunWithOptions(
    mut env: JNIEnv,
    _class: JClass,
    rt_id: jint,
    config_path: JString,
    auto_reload: jboolean,
    multi_thread: jboolean,
    auto_threads: jboolean,
    threads: jint,
    stack_size: jint,
) -> jint {
    let Ok(path) = env.get_string(&config_path) else {
        return ERR_CONFIG_PATH;
    };
    let path: String = path.into();
    let path_ptr = std::ffi::CString::new(path).unwrap();
    leaf_run_with_options(
        rt_id as u16,
        path_ptr.as_ptr(),
        auto_reload != 0,
        multi_thread != 0,
        auto_threads != 0,
        threads,
        stack_size,
    )
}

/// JNI: Reload leaf config.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn Java_com_follow_clash_core_LeafBridge_leafReload(
    _env: JNIEnv,
    _class: JClass,
    rt_id: jint,
) -> jint {
    leaf_reload(rt_id as u16)
}

/// JNI: Shutdown leaf.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn Java_com_follow_clash_core_LeafBridge_leafShutdown(
    _env: JNIEnv,
    _class: JClass,
    rt_id: jint,
) -> jboolean {
    leaf_shutdown(rt_id as u16) as jboolean
}

/// JNI: Test config.
#[cfg(target_os = "android")]
#[allow(non_snake_case)]
#[no_mangle]
pub unsafe extern "system" fn Java_com_follow_clash_core_LeafBridge_leafTestConfig(
    mut env: JNIEnv,
    _class: JClass,
    config_path: JString,
) -> jint {
    let Ok(path) = env.get_string(&config_path) else {
        return ERR_CONFIG_PATH;
    };
    let path: String = path.into();
    let path_ptr = std::ffi::CString::new(path).unwrap();
    leaf_test_config(path_ptr.as_ptr())
}
