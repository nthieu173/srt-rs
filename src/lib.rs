pub mod error;

mod socket;
pub use socket::SrtBuilder;
pub use socket::SrtSocket;

use libsrt_sys as srt;

use std::sync::Once;

static STARTUP: Once = Once::new();
pub fn startup() -> Result<(), error::SrtError> {
    let mut result = 0;
    STARTUP.call_once(|| unsafe {
        result = srt::srt_startup();
    });
    error::wrap_result((), result)
}

pub fn cleanup() -> Result<(), error::SrtError> {
    let result;
    unsafe {
        result = srt::srt_cleanup();
    }
    error::wrap_result((), result)
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
