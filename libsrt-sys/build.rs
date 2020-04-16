use std::env;
use std::process::Command;

fn main() {
    let build_dir = env::current_dir().unwrap();
    let mut tcl_shell = build_dir.clone();
    tcl_shell.push("tclkit");
    if cfg!(target_os = "windows") {
        tcl_shell.push("tclkit-8.6.3-win32-ix86.exe");
    } else {
        tcl_shell.push("tclkit-8.6.3-rhel5-ix86");
    }
    let mut configure = build_dir;
    configure.push("srt-src");
    configure.push("configure");
    let out_dir = env::var("OUT_DIR").unwrap();
    println!("{}", out_dir);
    env::set_current_dir(&out_dir).expect("failed to set current dir to libsrt");
    Command::new(tcl_shell)
        .arg(configure)
        .arg("--prefix")
        .arg(".")
        .output()
        .expect("failed to run configure");
    if cfg!(target_os = "windows") {
        Command::new("cmd")
            .arg("make install")
            .output()
            .expect("failed to run cmake");
    } else {
        Command::new("sh")
            .arg("-c")
            .arg("make install")
            .output()
            .expect("failed to run cmake");
    }
    println!("cargo:rustc-link-search={}", out_dir);
}
