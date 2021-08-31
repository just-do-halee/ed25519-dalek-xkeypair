// Licensed under either of Apache License, Version 2.0 or MIT license at your option.
// Copyright 2021 Hwakyeom Kim(=just-do-halee)

pub use utils_results::*;

err! {
    Hmac => "hmac error"
    Parser => "parser error"
    Ed25519 => "ed25519 error"
    Overflow => "overflow occurs"
    InvalidLenSize => "invalid len size:"
}
