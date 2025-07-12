use std::slice;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use zeroize::Zeroize;
use zxcvbn::{zxcvbn, Score::Three};
use zxcvbn::Score::Four;

fn convert_unicode_to_string(unicode_string: &UNICODE_STRING) -> String {
    let buffer =
        unsafe { slice::from_raw_parts(unicode_string.Buffer, unicode_string.Length as usize) };

    let result = String::from_utf16(&buffer);

    match result {
        Ok(_) => result.unwrap(),
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
    let mut account_name_string = convert_unicode_to_string(&account_full_name);
    let mut password_string = convert_unicode_to_string(&password);

    // Ensure Converted Strings Arent Empty
    if account_name_string.is_empty() || password_string.is_empty() {
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
    let strength_estimate = zxcvbn(password_string.as_str(), &[account_name_string.as_str()]);

    // Zero out String, Not Needed anymore
    account_name_string.zeroize();
    password_string.zeroize();

    if strength_estimate.score() < Four {
        eprintln!("Score > {}", strength_estimate.score());
        return false;
    }

    true
}
