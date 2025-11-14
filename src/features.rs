/// Checks that only one feature from the list is enabled
macro_rules! mutually_exclusive {
    ($feat:literal, $($other:literal),+ $(,)?) => {
        #[cfg(all(feature = $feat, any($(feature = $other),+)))]
        compile_error!("strength* features are mutually exclusive");
    };
}

// Use it like this
mutually_exclusive!("strength1", "strength2", "strength3", "strength4");
mutually_exclusive!("strength2", "strength1", "strength3", "strength4");
mutually_exclusive!("strength3", "strength1", "strength2", "strength4");
mutually_exclusive!("strength4", "strength1", "strength2", "strength3");
