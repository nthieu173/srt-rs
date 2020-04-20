use std::{env, error::Error, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    if cfg!(windows) {
        println!(
            "cargo:rustc-link-search={}",
            env::var("SRT_LIB_DIR").expect("SRT_LIB_DIR not set")
        );
    } else {
        let mut configure = PathBuf(env::current_dir()?);
        configure.push("srt-src");
        configure.push("configure");
        env::set_current_dir(env::var("OUT_DIR")?).expect("failed to set current dir to libsrt");
        let output = Command::new("tclsh")
            .arg(configure)
            .arg("--enable-apps=OFF")
            .arg("--prefix=.")
            .output()
            .expect("failed to run configure in tclsh");
        if !String::from_utf8(output.stdout)?.contains("Build files have been written to") {
            panic!("failed to generate build files");
        }
        Command::new("sh")
            .arg("-c")
            .arg("make install")
            .output()
            .expect("failed to run cmake in sh");
        println!("cargo:rustc-link-search={}", env::var("OUT_DIR")?);
    }
    Ok(())
}
