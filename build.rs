fn main() {
    #[cfg(any(feature = "tls-native-tls", feature = "tls-rustls"))]
    {
        println!("cargo::rustc-check-cfg=cfg(tls)");
        println!("cargo:rustc-cfg=tls");
    }
}
