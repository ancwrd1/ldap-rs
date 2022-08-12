#[cfg(all(feature = "tls-native-tls", feature = "tls-rustls"))]
compile_error!("Please specify one of tls-native-tls or tls-rustls, but not both");

fn main() {
    #[cfg(any(feature = "tls-native-tls", feature = "tls-rustls"))]
    println!("cargo:rustc-cfg=tls");
}
