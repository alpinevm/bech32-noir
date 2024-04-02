# Bech32 Noir 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**This software is not audited, use at your own risk.**

<hr>

**Bech32 Noir** provides functions for decoding the locking script components (P2WSH, P2WPKH) from bitcoin [segwit addresses](https://en.bitcoin.it/wiki/BIP_0173#Bech32) in Noir Circuits.

At the moment, this library only supports decoding.
<br>

## Installation

In your `Nargo.toml` file, add the following dependency:

```toml
[dependencies]
bech32 = { tag = "v0.1.0", git = "https://github.com/alpinevm/bech32-noir" }
```

### Example Usage

```rust
use dep::bech32;

fn main(
    address: str<42>, // example address: bc1q3x5ecspn9jjp9ah33000lcnrx35s0kq7f8tyan
    pub_key_hash: [u8; 20] // example hash: 89a99c40332ca412f6f18bdeffe263346907d81e (encoded as array of u8s)
) -> pub Field {
    let address_bvec: BoundedVec<u8, 90> = bech32::str_to_bvec(address);
    let witness = bech32::segwit_decode(address_bvec);
    // hardcoded version '0' given the above address
    assert(witness == bech32::witness_builder(0, pub_key_hash));
}
    
```

### Benchmark 
```rust
use dep::bech32;
fn main() {
    let data: BoundedVec<u8, 90> = bech32::str_to_bvec("bc1qsktu2fffyuwkmxk85z4ad9mq9hhldqqcnrzmzs");
    let witness_program = bech32::segwit_decode(data);
}
```
```sh
% nargo info
+-------------+----------------------+--------------+----------------------+
| Package     | Expression Width     | ACIR Opcodes | Backend Circuit Size |
+-------------+----------------------+--------------+----------------------+
| bech32_test | Bounded { width: 3 } | 22405        | 27126                |
+-------------+----------------------+--------------+----------------------+
```
