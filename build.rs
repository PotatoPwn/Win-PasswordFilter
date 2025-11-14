fn main() {
    cfg_if::cfg_if! {
        if #[cfg(feature = "strength2")] {
            println!("cargo:warning=Strength level Two is not recommended.");
        } else if #[cfg(feature = "strength1")] {
            println!("cargo:warning=Strength level One is not recommended.");
        }
    }
}
