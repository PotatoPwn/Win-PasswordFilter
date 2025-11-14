use fake::{
    faker::internet::en::{Password, Username},
    Fake,
};
use lsass_pass_filter::password_filter::PasswordFilter;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::UNICODE_STRING;

struct UnicodeString {
    inner: UNICODE_STRING,
    _buffer: Vec<u16>,
}

fn string_to_unicode(string_value: &str) -> UnicodeString {
    let mut buffer: Vec<u16> = string_value.encode_utf16().collect();
    buffer.push(0);

    UnicodeString {
        inner: UNICODE_STRING {
            Buffer: buffer.as_ptr() as PWSTR,
            Length: (string_value.len() * 2) as u16,
            MaximumLength: ((string_value.len() + 1) * 2) as u16,
        },
        _buffer: buffer,
    }
}

#[test]
fn valid_secure_password() {
    let username = "lie2aePh3ahl";
    let full_name = "Name";
    let password = "aejuiPheeBafaM8Seikae9eipah7ped2";

    assert!(PasswordFilter(
        string_to_unicode(&username).inner,
        string_to_unicode(&full_name).inner,
        string_to_unicode(&password).inner,
        true,
    ));
}

#[test]
fn name_in_password_rejected() {
    let username = "username";
    let full_name = "Bobby";
    let password = "Bobby123!";

    // Assert that this will fail
    assert!(!PasswordFilter(
        string_to_unicode(&username).inner,
        string_to_unicode(&full_name).inner,
        string_to_unicode(&password).inner,
        true,
    ));
}

#[test]
fn username_in_password_rejected() {
    let username = "username";
    let full_name = "Bobby";
    let password = "username123!";

    // Assert that this will fail
    assert!(!PasswordFilter(
        string_to_unicode(&username).inner,
        string_to_unicode(&full_name).inner,
        string_to_unicode(&password).inner,
        true,
    ));
}

#[test]
fn test_run() {
    for _n in 1..100 {
        let username: String = Username().fake::<String>();

        let full_name: String = fake::faker::name::en::FirstName().fake();

        let mut rng = rand::rng();

        let password: String = Password(32..50).fake_with_rng(&mut rng);

        println!(
            "Username > {}, Password > {}, Full name > {}",
            username, password, full_name
        );

        assert!(PasswordFilter(
            string_to_unicode(&username).inner,
            string_to_unicode(&full_name).inner,
            string_to_unicode(&password).inner,
            true,
        ));
    }
}
