use std::{env, error::Error, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let build_dir = env::current_dir()?;
    let mut configure = build_dir.clone();
    configure.push("srt-src");
    configure.push("configure");
    let out_dir = env::var("OUT_DIR")?;
    env::set_current_dir(&out_dir).expect("failed to set current dir to libsrt");
    if cfg!(windows) {
        let mut tcl_shell = build_dir;
        tcl_shell.push("tclkit");
        tcl_shell.push("tclkit-cli-8_6_10-twapi-4_3_8-x86-max.exe");
        let mut configure_command = Command::new(tcl_shell);
        configure_command
            .arg(configure)
            .arg("--enable-apps=OFF")
            .arg(format!(
                "--pthread-include-dir={}",
                env::var("PTHREAD_INCLUDE_DIR")?
            ))
            .arg("--prefix=.");
        if let Ok(openssl_include_dir) = env::var("OPENSSL_INCLUDE_DIR") {
            configure_command.arg(format!("--openssl-include-dir={}", openssl_include_dir));
        }
        let output = configure_command.output().expect("failed to configure");
        if !String::from_utf8(output.stdout)?.contains("Build files have been written to") {
            panic!("failed to generate build files");
        }
        Command::new("cmd")
            .arg("make install")
            .output()
            .expect("failed to run cmake");
        println!("cargo:rustc-link-search={}", out_dir);
    } else {
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
            .expect("failed to run cmake");
        println!("cargo:rustc-link-search={}", out_dir);
    }
    Ok(())
}
