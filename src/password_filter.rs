use std::slice;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use zeroize::Zeroize;
use zxcvbn::zxcvbn;

use zxcvbn::Score;
#[allow(unused_imports)]
use zxcvbn::Score::{Four, Three};

#[cfg(all(feature = "strength3", feature = "strength4"))]
compile_error!("Only one \"strength\" feature can be enabled at once");

cfg_if::cfg_if! {
    if #[cfg(feature = "strength4")] {
        const PASSWORD_STRENGTH: Score = Four;
    } else if #[cfg(feature = "strength3")] {
        const PASSWORD_STRENGTH: Score = Three;
    } else {
        // Explicitly default to three.
        const PASSWORD_STRENGTH: Score = Three;
    }
}

fn convert_unicode_to_string(unicode_string: &UNICODE_STRING) -> String {
    let buffer = unsafe {
        slice::from_raw_parts(unicode_string.Buffer, (unicode_string.Length as usize) / 2)
    };

    let result = String::from_utf16(&buffer);

    match result {
        Ok(value) => value,
        Err(_) => String::from(""),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn PasswordFilter(
    account_name: UNICODE_STRING,
    account_full_name: UNICODE_STRING,
    password: UNICODE_STRING,
    set_operation: bool,
) -> bool {
    // Ensure Content isnt Empty :)
    if account_name.Length == 0 || account_full_name.Length == 0 || password.Length == 0 {
        eprintln!("Invalid Parameters");
        return false;
    }

    // Requesting a Password Change
    if !set_operation {
        return false;
    }

    // Convert Unicode Values into String for Easier Handling
    let mut account_name_string = convert_unicode_to_string(&account_name);
    let mut account_full_name_string = convert_unicode_to_string(&account_full_name);
    let mut password_string = convert_unicode_to_string(&password);

    // Ensure Converted Strings Arent Empty
    if account_name_string.is_empty() || password_string.is_empty() {
        eprintln!(
            "Strings ({}) and ({}) are empty",
            account_name_string, password_string
        );
        return false;
    }

    // Ensure the Account Name isnt Container inside the Password
    if account_name_string.contains(&password_string) {
        eprintln!("Password Contains Username");

        // Zero out the Sensitive Account Name & String
        account_name_string.zeroize();
        password_string.zeroize();

        return false;
    }

    // Run ZXCVBN Check
    let strength_estimate = zxcvbn(
        password_string.as_str(),
        &[
            account_full_name_string.as_str(),
            account_name_string.as_str(),
        ],
    );

    // Zero out String, Not Needed anymore
    account_name_string.zeroize();
    account_full_name_string.zeroize();
    password_string.zeroize();

    eprintln!("Score == {}", strength_estimate.score());
    eprintln!("{:?}", strength_estimate.sequence());

    if strength_estimate.score() < PASSWORD_STRENGTH {
        eprintln!("Score > {}", strength_estimate.score());
        return false;
    }

    true
}
