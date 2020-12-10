use bindgen;
use cmake;

use std::{env, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(unix) {
        let dst = cmake::Config::new("libsrt")
            .define("ENABLE_APPS", "OFF")
            .build();
        let mut lib_dir = PathBuf::from(dst);
        lib_dir.push("lib");
        println!("cargo:rustc-link-search={}", lib_dir.display());
        println!("cargo:rustc-link-lib=srt");
    } else if cfg!(windows) {
        let dst = cmake::Config::new("libsrt")
            .generator("Visual Studio 16 2019")
            .define("ENABLE_STDCXX_SYNC", "ON")
            .define("ENABLE_APPS", "OFF")
            .build();
        let mut lib_dir = PathBuf::from(dst);
        lib_dir.push("lib");
        println!("cargo:rustc-link-search={}", lib_dir.display());
        println!("cargo:rustc-link-lib=srt");
    }

    let mut include_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    include_path.push("include");
    include_path.push("srt");

    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .clang_arg(format!(
            "-I/{}",
            include_path.as_os_str().to_str().expect("malformed path")
        ))
        .size_t_is_usize(true)
        .whitelist_function("srt_.*")
        .whitelist_type("SRT.*")
        .whitelist_var("SRT.*")
        .default_enum_style(bindgen::EnumVariation::NewType { is_bitfield: false })
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
    Ok(())
}
