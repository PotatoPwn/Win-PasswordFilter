use fake::{
    faker::internet::en::{Password, Username},
    Fake,
};
use rand::seq::IndexedRandom;
use windows_sys::core::PWSTR;
use windows_sys::Win32::Foundation::UNICODE_STRING;
use Passfilt::password_filter::PasswordFilter;

fn string_to_unicode(string_value: String) -> UNICODE_STRING {
    let buffer: Vec<u16> = string_value.encode_utf16().collect();

    UNICODE_STRING {
        Buffer: buffer.as_ptr() as PWSTR,
        Length: string_value.len() as u16,
        MaximumLength: string_value.len() as u16,
    }
}

#[test]
fn test_run() {
    for _n in 1..100 {
        let username = Username().fake();

        let full_name = fake::faker::name::en::FirstName().fake();

        let mut rng = rand::rng();

        let password = Password(4..20).fake_with_rng(&mut rng);

        println!(
            "Username > {}, Password > {}, Full name > {}",
            username, password, full_name
        );

        if PasswordFilter(
            string_to_unicode(username),
            string_to_unicode(full_name),
            string_to_unicode(password),
            true,
        ) {
            println!("Passed!")
        } else {
            eprintln!("Failed!")
        }

        println!()
    }
}
