use cmake;
use std::path::PathBuf;

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
    Ok(())
}
