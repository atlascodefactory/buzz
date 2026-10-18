/// Seconds since the last OS-wide user input (keyboard/mouse anywhere on the
/// machine), or `None` on platforms without a supported idle API (Linux
/// Wayland). Callers fall back to in-app activity tracking when `None`.
#[tauri::command]
pub fn get_os_idle_seconds() -> Option<u64> {
    #[cfg(target_os = "macos")]
    {
        use objc2_core_graphics::{CGEventSource, CGEventSourceStateID, CGEventType};

        // Apple's kCGAnyInputEventType includes input outside this app.
        let seconds = CGEventSource::seconds_since_last_event_type(
            CGEventSourceStateID::HIDSystemState,
            CGEventType(u32::MAX),
        );
        idle_seconds(seconds)
    }
    #[cfg(windows)]
    {
        user_idle::UserIdle::get_time()
            .ok()
            .map(|idle| idle.as_seconds())
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        None
    }
}

#[cfg(any(target_os = "macos", test))]
fn idle_seconds(seconds: f64) -> Option<u64> {
    (seconds.is_finite() && seconds >= 0.0 && seconds < u64::MAX as f64).then_some(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::idle_seconds;

    #[test]
    #[cfg(target_os = "macos")]
    fn native_idle_api_returns_seconds() {
        assert!(super::get_os_idle_seconds().is_some());
    }

    #[test]
    fn preserves_whole_seconds_and_rejects_unavailable_values() {
        assert_eq!(idle_seconds(0.0), Some(0));
        assert_eq!(idle_seconds(12.75), Some(12));
        for invalid in [-1.0, f64::NAN, f64::INFINITY, u64::MAX as f64] {
            assert_eq!(idle_seconds(invalid), None);
        }
    }
}
