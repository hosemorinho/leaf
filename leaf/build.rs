use std::{
    env,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn resolve_android_prebuilt_dir() -> Option<PathBuf> {
    let ndk = env::var("ANDROID_NDK")
        .or_else(|_| env::var("ANDROID_NDK_HOME"))
        .or_else(|_| env::var("ANDROID_NDK_LATEST_HOME"))
        .or_else(|_| env::var("NDK_HOME"))
        .ok()?;

    let prebuilt = Path::new(&ndk).join("toolchains").join("llvm").join("prebuilt");
    let candidates = [
        "windows-x86_64",
        "linux-x86_64",
        "darwin-arm64",
        "darwin-x86_64",
    ];
    for candidate in candidates {
        let host_dir = prebuilt.join(candidate);
        if host_dir.exists() {
            return Some(host_dir);
        }
    }

    if let Ok(entries) = fs::read_dir(&prebuilt) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                return Some(entry.path());
            }
        }
    }
    None
}

fn resolve_android_sysroot() -> Option<PathBuf> {
    resolve_android_prebuilt_dir().map(|d| d.join("sysroot"))
}

fn resolve_android_clang_include() -> Option<PathBuf> {
    let prebuilt = resolve_android_prebuilt_dir()?;
    let clang_root = prebuilt.join("lib").join("clang");
    let mut versions: Vec<PathBuf> = fs::read_dir(&clang_root)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    versions.sort();
    versions.reverse();
    for version_dir in versions {
        let include = version_dir.join("include");
        if include.exists() {
            return Some(include);
        }
    }
    None
}

fn generate_mobile_bindings() {
    println!("cargo:rerun-if-changed=src/mobile/wrapper.h");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mut builder = bindgen::Builder::default()
        .header("src/mobile/wrapper.h")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // https://github.com/rust-lang/rust-bindgen/issues/1211
            "--target=arm64-apple-ios"
        } else {
            ""
        })
        .clang_arg(if arch == "aarch64" && os == "ios" {
            // sdk path find by `xcrun --sdk iphoneos --show-sdk-path`
            let output = Command::new("xcrun")
                .arg("--sdk")
                .arg("iphoneos")
                .arg("--show-sdk-path")
                .output()
                .expect("failed to execute xcrun");
            let inc_path =
                Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("usr/include");
            format!("-I{}", inc_path.to_str().expect("invalid include path"))
        } else {
            "".to_string()
        });

    if os == "android" {
        if let Ok(target) = env::var("TARGET") {
            builder = builder.clang_arg(format!("--target={target}"));
        }
        if let Some(sysroot) = resolve_android_sysroot() {
            let sysroot = sysroot.to_string_lossy().to_string();
            builder = builder.clang_arg(format!("--sysroot={sysroot}"));
        }
        if let Some(clang_include) = resolve_android_clang_include() {
            builder = builder.clang_arg(format!("-I{}", clang_include.to_string_lossy()));
        }
    }

    let bindings = builder
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("mobile_bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "ios" || os == "macos" {
        generate_mobile_bindings();
    }

    if env::var("PROTO_GEN").is_ok() {
        // println!("cargo:rerun-if-changed=src/config/internal/config.proto");
        protobuf_codegen::Codegen::new()
            .out_dir("src/config/internal")
            .includes(["src/config/internal"])
            .inputs(["src/config/internal/config.proto"])
            .customize(
                protobuf_codegen::Customize::default()
                    .generate_accessors(false)
                    .gen_mod_rs(false)
                    .lite_runtime(true),
            )
            .run()
            .expect("Protobuf code gen failed");

        // println!("cargo:rerun-if-changed=src/config/geosite.proto");
        protobuf_codegen::Codegen::new()
            .out_dir("src/config")
            .includes(["src/config"])
            .inputs(["src/config/geosite.proto"])
            .customize(
                protobuf_codegen::Customize::default()
                    .generate_accessors(false)
                    .gen_mod_rs(false)
                    .lite_runtime(true),
            )
            .run()
            .expect("Protobuf code gen failed");

        protobuf_codegen::Codegen::new()
            .out_dir("src/app/outbound")
            .includes(["src/app/outbound"])
            .inputs(["src/app/outbound/selector_cache.proto"])
            .customize(
                protobuf_codegen::Customize::default()
                    .generate_accessors(false)
                    .gen_mod_rs(false)
                    .lite_runtime(true),
            )
            .run()
            .expect("Protobuf code gen failed");
    }
}
