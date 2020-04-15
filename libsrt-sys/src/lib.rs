pub mod error;

mod socket;
pub use socket::SrtBuilder;
pub use socket::SrtSocket;

use libc::c_int;

use std::sync::Once;

enum StartupStatus {
    NotStarted,
    Started,
}

static STARTUP: Once = Once::new();
pub fn startup() -> Result<(), error::SrtError> {
    let mut result = 0;
    STARTUP.call_once(|| unsafe {
        result = srt_startup();
    });
    error::wrap_result((), result)
}

pub fn cleanup() -> Result<(), error::SrtError> {
    let result;
    unsafe {
        result = srt_cleanup();
    }
    error::wrap_result((), result)
}

#[link(name = "srt")]
extern "C" {
    fn srt_startup() -> c_int;
    fn srt_cleanup() -> c_int;
}

#[cfg(test)]
mod tests {
    use crate as srt;
    #[test]
    fn test_startup_cleanup() {
        assert!(srt::startup().is_ok());
        assert!(srt::cleanup().is_ok());
    }
}
