use std::{env, error::Error, path::PathBuf, process::Command};

#[cfg(windows)]
use std::{
    fs::{self, DirEntry},
    path::Path,
};

#[cfg(windows)]
const MIN_VS_VERSION: u32 = 2017;

fn main() -> Result<(), Box<dyn Error>> {
    let mut configure =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not found"));
    configure.push("srt-src");
    configure.push("configure");
    let out_dir = env::var("OUT_DIR")?;
    env::set_current_dir(&out_dir).expect("failed to set current dir to out_dir");
    if cfg!(windows) {
        make_install(configure);
        println!("cargo:rustc-link-search={}\\Release", out_dir);
    } else {
        make_install(configure);
        println!("cargo:rustc-link-search={}", out_dir);
    }
    Ok(())
}

#[cfg(windows)]
fn make_install(configure: PathBuf) {
    let mut tcl_shell =
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not found"));
    tcl_shell.push("tclkit");
    tcl_shell.push("tclkit-cli-8_6_10-twapi-4_3_8-x64-max.exe");
    let mut configure_command = Command::new(tcl_shell);
    configure_command
        .arg(configure)
        .arg("--enable-apps=OFF")
        .arg(format!(
            "--pthread-include-dir={}",
            env::var("PTHREAD_INCLUDE_DIR").expect("PTHREAD_INCLUDE_DIR not set")
        ))
        .arg("--prefix=.");
    if let Ok(openssl_include_dir) = env::var("OPENSSL_INCLUDE_DIR") {
        configure_command.arg(format!("--openssl-include-dir={}", openssl_include_dir));
    }
    let output = String::from_utf8(
        configure_command
            .output()
            .expect("failed to configure")
            .stdout,
    )
    .expect("malformed configure output");
    if !output.contains("Build files have been written to") {
        println!("{}", output);
        panic!("failed to generate build files");
    }
    let mut visual_studios: Vec<DirEntry> = fs::read_dir(Path::new(
        "C:\\Program Files (x86)\\Microsoft Visual Studio",
    ))
    .expect("fail to read Visual Studio dir")
    .filter(|f| f.is_ok())
    .map(|f| f.unwrap())
    .filter(|f| f.file_type().is_ok() && f.file_type().unwrap().is_dir())
    .filter(|f| {
        if let Ok(name) = f.file_name().into_string() {
            if let Ok(version) = name.parse::<u32>() {
                return version >= MIN_VS_VERSION;
            }
        }
        false
    })
    .collect();
    if visual_studios.len() == 0 {
        panic!("Only Visual Studio {} and up is supported", 2017);
    }
    visual_studios.sort_unstable_by_key(|f| f.file_name());
    visual_studios.reverse();
    let mut command_files = Vec::new();
    for entry in visual_studios {
        let mut bat = fs::read_dir(entry.path())
            .expect("fail to read Visual Studio dir")
            .filter(|f| f.is_ok())
            .map(|f| f.unwrap())
            .filter(|f| f.file_type().is_ok() && f.file_type().unwrap().is_dir())
            .filter(|f| {
                if let Ok(name) = f.file_name().into_string() {
                    return ["Community", "Professional", "Enterprise"].contains(&name.as_str());
                }
                false
            })
            .map(|f| {
                let mut p = f.path();
                p.push("VC");
                p.push("Auxiliary");
                p.push("Build");
                p.push("vcvars64.bat");
                p
            })
            .collect();
        command_files.append(&mut bat);
    }
    for command_file in command_files.iter().filter(|p| p.exists()) {
        if let Ok(output) = Command::new("cmd").arg("/c").arg(command_file).output() {
            if let Ok(out) = String::from_utf8(output.stdout) {
                if out.contains("[vcvarsall.bat] Environment initialized for: 'x64'") {
                    Command::new("cmd")
                        .arg("/c")
                        .arg(command_file)
                        .args(&[
                            "&&", "cmake", "--build", ".", "--config", "Release", "--target",
                            "install",
                        ])
                        .output()
                        .expect("failed to run cmake");
                    return;
                }
            }
        }
    }
    panic!("No vcvars64.bat file found");
}

#[cfg(unix)]
fn make_install(configure: PathBuf) {
    let output = Command::new("tclsh")
        .arg(configure)
        .arg("--enable-apps=OFF")
        .arg("--prefix=.")
        .output()
        .expect("failed to run configure in tclsh");
    if !String::from_utf8(output.stdout)
        .expect("malformed configure output")
        .contains("Build files have been written to")
    {
        panic!("failed to generate build files");
    }
    Command::new("sh")
        .arg("-c")
        .arg("make install")
        .output()
        .expect("failed to run cmake");
}
