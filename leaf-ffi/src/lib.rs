#![allow(clippy::missing_safety_doc)]
use std::{ffi::CStr, os::raw::c_char, ptr};

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

fn to_runtime_opt(
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> leaf::RuntimeOption {
    if !multi_thread {
        return leaf::RuntimeOption::SingleThread;
    }
    if auto_threads {
        return leaf::RuntimeOption::MultiThreadAuto(stack_size as usize);
    }
    leaf::RuntimeOption::MultiThread(threads as usize, stack_size as usize)
}

fn write_bytes_to_buf(bytes: &[u8], buf: *mut c_char, buf_len: i32) -> i32 {
    if buf.is_null() || buf_len <= 0 {
        return ERR_CONFIG_PATH;
    }
    // Need one extra byte for NUL terminator.
    let required = bytes.len() + 1;
    if required > buf_len as usize {
        return -(required as i32);
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), bytes.len());
        *buf.add(bytes.len()) = 0;
    }
    bytes.len() as i32
}

fn write_string_to_buf(s: &str, buf: *mut c_char, buf_len: i32) -> i32 {
    write_bytes_to_buf(s.as_bytes(), buf, buf_len)
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

#[no_mangle]
pub unsafe extern "C" fn leaf_run_with_options_config_string(
    rt_id: u16,
    config: *const c_char,
    multi_thread: bool,
    auto_threads: bool,
    threads: i32,
    stack_size: i32,
) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        let opts = leaf::StartOptions {
            config: leaf::Config::Str(config.to_string()),
            #[cfg(feature = "auto-reload")]
            auto_reload: false,
            runtime_opt: to_runtime_opt(multi_thread, auto_threads, threads, stack_size),
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

#[no_mangle]
pub unsafe extern "C" fn leaf_reload_with_config_string(
    rt_id: u16,
    config: *const c_char,
) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        if let Err(e) = leaf::reload_with_config_string(rt_id, config) {
            return to_errno(e);
        }
        ERR_OK
    } else {
        ERR_CONFIG_PATH
    }
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

#[no_mangle]
pub extern "C" fn leaf_close_connections(_rt_id: u16) -> bool {
    // The current leaf core does not expose a stable API for forcing all
    // active relays closed from FFI. Keep the symbol for ABI compatibility.
    false
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

#[no_mangle]
pub unsafe extern "C" fn leaf_test_config_string(config: *const c_char) -> i32 {
    if let Ok(config) = unsafe { CStr::from_ptr(config).to_str() } {
        if let Err(e) = leaf::config::from_string(config).map(|_| ()) {
            return to_errno(leaf::Error::Config(e));
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

#[no_mangle]
pub unsafe extern "C" fn leaf_health_check_with_latency(
    rt_id: u16,
    outbound_tag: *const c_char,
    timeout_ms: u64,
    tcp_ms: *mut u64,
    udp_ms: *mut u64,
) -> i32 {
    use std::time::Duration;

    if tcp_ms.is_null() || udp_ms.is_null() {
        return ERR_CONFIG_PATH;
    }

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
            let tcp_ok = tcp_res.is_ok();
            let udp_ok = udp_res.is_ok();
            unsafe {
                *tcp_ms = tcp_res
                    .as_ref()
                    .ok()
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                *udp_ms = udp_res
                    .as_ref()
                    .ok()
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
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

#[no_mangle]
pub unsafe extern "C" fn leaf_set_outbound_selected(
    rt_id: u16,
    outbound: *const c_char,
    select: *const c_char,
) -> i32 {
    let outbound = if let Ok(v) = unsafe { CStr::from_ptr(outbound).to_str() } {
        v.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };
    let select = if let Ok(v) = unsafe { CStr::from_ptr(select).to_str() } {
        v.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        #[cfg(feature = "outbound-select")]
        {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move { m.set_outbound_selected(&outbound, &select).await })
        }
        #[cfg(not(feature = "outbound-select"))]
        {
            let _ = m;
            Err(leaf::Error::RuntimeManager)
        }
    } else {
        Err(leaf::Error::RuntimeManager)
    };

    match result {
        Ok(()) => ERR_OK,
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn leaf_get_outbound_selected(
    rt_id: u16,
    outbound: *const c_char,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    let outbound = if let Ok(v) = unsafe { CStr::from_ptr(outbound).to_str() } {
        v.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        #[cfg(feature = "outbound-select")]
        {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move { m.get_outbound_selected(&outbound).await })
        }
        #[cfg(not(feature = "outbound-select"))]
        {
            let _ = m;
            Err(leaf::Error::RuntimeManager)
        }
    } else {
        Err(leaf::Error::RuntimeManager)
    };

    match result {
        Ok(selected) => write_string_to_buf(&selected, buf, buf_len),
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub unsafe extern "C" fn leaf_get_outbound_selects(
    rt_id: u16,
    outbound: *const c_char,
    buf: *mut c_char,
    buf_len: i32,
) -> i32 {
    let outbound = if let Ok(v) = unsafe { CStr::from_ptr(outbound).to_str() } {
        v.to_string()
    } else {
        return ERR_CONFIG_PATH;
    };

    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let result = if let Some(m) = manager {
        #[cfg(feature = "outbound-select")]
        {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async move { m.get_outbound_selects(&outbound).await })
        }
        #[cfg(not(feature = "outbound-select"))]
        {
            let _ = m;
            Err(leaf::Error::RuntimeManager)
        }
    } else {
        Err(leaf::Error::RuntimeManager)
    };

    match result {
        Ok(selects) => match serde_json::to_string(&selects) {
            Ok(json) => write_string_to_buf(&json, buf, buf_len),
            Err(_) => ERR_IO,
        },
        Err(e) => to_errno(e),
    }
}

#[no_mangle]
pub extern "C" fn leaf_get_stats(rt_id: u16, buf: *mut c_char, buf_len: i32) -> i32 {
    let manager = leaf::RUNTIME_MANAGER.lock().unwrap().get(&rt_id).cloned();
    let Some(manager) = manager else {
        return ERR_RUNTIME_MANAGER;
    };

    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ERR_IO,
    };

    let json = rt.block_on(async move {
        let sm = manager.stat_manager();
        let sm = sm.read().await;
        let stats: Vec<_> = sm
            .counters
            .iter()
            .map(|c| {
                serde_json::json!({
                    "network": c.sess.network.to_string(),
                    "inbound_tag": c.sess.inbound_tag,
                    "forwarded_source": c.sess.forwarded_source.map(|x| x.to_string()),
                    "source": c.sess.source.to_string(),
                    "destination": c.sess.destination.to_string(),
                    "outbound_tag": c.sess.outbound_tag,
                    "bytes_sent": c.bytes_sent(),
                    "bytes_recvd": c.bytes_recvd(),
                    "send_completed": c.send_completed(),
                    "recv_completed": c.recv_completed(),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&stats)
    });

    match json {
        Ok(json) => write_string_to_buf(&json, buf, buf_len),
        Err(_) => ERR_IO,
    }
}

#[no_mangle]
pub unsafe extern "C" fn leaf_set_env(key: *const c_char, value: *const c_char) {
    let key = if let Ok(v) = unsafe { CStr::from_ptr(key).to_str() } {
        v
    } else {
        return;
    };
    let value = if let Ok(v) = unsafe { CStr::from_ptr(value).to_str() } {
        v
    } else {
        return;
    };
    std::env::set_var(key, value);
}

#[no_mangle]
pub extern "C" fn leaf_free_string(_s: *const c_char) {
    // String values are currently written into caller-provided buffers.
    // Keep this symbol as a no-op for ABI compatibility.
}
