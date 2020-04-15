use std::path::PathBuf;
use std::process::Command;

fn main() {
    run_configure();
}

fn run_configure() {
    let mut tcl_shell = PathBuf::from("tclkit");
    if cfg!(target_os = "windows") {
        tcl_shell.push("tclkit-8.6.3-win32-ix86.exe");
    } else {
        tcl_shell.push("tclkit-8.6.3-rhel5-ix86");
    }
    let mut configure = PathBuf::from("srt-src");
    configure.push("configure");
    Command::new(tcl_shell)
        .current_dir("libsrt")
        .arg(configure)
        .arg("--prefix")
        .output()
        .expect("failed to execute process");
}
