# srp proxy
This is a little proxy i made for private wow authentication servers to validate SRP packets to prevent useless TCP flood.
This does not protect against SYN flood attacks due to the kernel itself handling it and not tokio handling it.
Pretty much all implemented features are under `src/config.rs` excluding the connection timeout (wip, cba).

### How do i use this?
1. Install rust via [rustup.sh](https://rustup.sh)
2. Compile using `cargo build`
3. Configure the config.json to your liking.
4. Use `cargo run` to start the proxy.
