pub mod error;

mod socket;
pub use socket::SrtBuilder;
pub use socket::SrtSocket;

use libc;
use libsrt_sys as srt;
use std::sync::Once;

static STARTUP: Once = Once::new();

pub fn startup() -> Result<(), error::SrtError> {
    let mut result = 0;
    STARTUP.call_once(|| unsafe {
        result = srt::srt_startup();
        libc::atexit(cleanup);
    });
    error::wrap_result((), result)
}

extern "C" fn cleanup() {
    unsafe {
        srt::srt_cleanup();
    }
}

#[cfg(test)]
mod tests {
    use crate as srt;

    #[test]
    fn test_startup() {
        assert!(srt::startup().is_ok());
    }
}
