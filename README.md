# ***`ed25519-dalek-xkeypair`***

[![CI][ci-badge]][ci-url]
[![Crates.io][crates-badge]][crates-url]
[![Licensed][license-badge]][license-url]
[![Twitter][twitter-badge]][twitter-url]

[ci-badge]: https://github.com/just-do-halee/ed25519-dalek-xkeypair/actions/workflows/ci.yml/badge.svg
[crates-badge]: https://img.shields.io/crates/v/ed25519-dalek-xkeypair.svg?labelColor=383636
[license-badge]: https://img.shields.io/crates/l/ed25519-dalek-xkeypair?labelColor=383636
[twitter-badge]: https://img.shields.io/twitter/follow/do_halee?style=flat&logo=twitter&color=4a4646&labelColor=333131&label=just-do-halee

[ci-url]: https://github.com/just-do-halee/ed25519-dalek-xkeypair/actions
[twitter-url]: https://twitter.com/do_halee
[crates-url]: https://crates.io/crates/ed25519-dalek-xkeypair
[license-url]: https://github.com/just-do-halee/ed25519-dalek-xkeypair


*BIP32 implementation for ed25519-dalek key pairs.*

| [Docs](https://docs.rs/ed25519-dalek-xkeypair) | [Latest Note](https://github.com/just-do-halee/ed25519-dalek-xkeypair/blob/main/CHANGELOG.md) |

```toml
[dependencies]
ed25519-dalek-xkeypair = "1.0.2"
```

## No-std

Disable default feature(allocator is needed).

```toml
[dependencies]
ed25519-dalek-xkeypair = { version = "1.0.2", default-features = false }
```

## License:
* MIT OR Apache-2.0
