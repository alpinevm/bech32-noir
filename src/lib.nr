// Adapted from the original reference implementation (python + rust primarily):
// https://github.com/sipa/bech32
use dep::std;

mod bech32;

struct WitnessProgram {
    /// Witness program version
    version: u8,
    /// Witness program content
    program: BoundedVec<u8, 90>
}

impl Eq for WitnessProgram {
    fn eq(self, other: Self) -> bool {
		let mut out = true;
		if self.version != other.version {
			out = false;
		}
		if self.program.len() != other.program.len() {
			out = false;
		}
		for i in 0..self.program.max_len() {
			if i < self.program.len() {
				if self.program.get_unchecked(i) != other.program.get_unchecked(i) {
					out = false;
				}
			}
		}
		out	
	}
}

// address should be P2WPKH or P2WSH with maximum of 90 characters
// output is version code + 20 byte hash of pub key/script
pub fn segwit_decode(address: BoundedVec<u8, 90>) -> WitnessProgram {
    let bech_resp = bech32::Bech32::decode(address);
    let decoded_data = bech32::Bech32::convert_to_higher_bits(bech_resp.data);
    assert((decoded_data.len() >= 2) & (decoded_data.len() <= 40), "segwit_decode::InvalidLength");
    assert(!(bech_resp.data.get(0) > 16), "segwit_decode::InvalidVersion");
    assert(
        !((bech_resp.data.get(0) == 0) & (decoded_data.len() != 20) & (decoded_data.len() != 32)), "segwit_decode::VersionMismatch"
    );
    assert(
        !((bech_resp.data.get(0) == 0) & (bech_resp.spec != bech32::ENCODING_BECH32)
        | (bech_resp.data.get(0) != 0) & (bech_resp.spec != bech32::ENCODING_BECH32M)), "segwit_decode::SpecMismatch"
    );
    WitnessProgram { version: bech_resp.data.get(0), program: decoded_data }
}

pub fn witness_builder<N>(v: u8, witness_array: [u8; N]) -> WitnessProgram {
    let mut witness = WitnessProgram { version: v, program: BoundedVec::new() };
    witness.program.extend_from_array(witness_array);
    witness
}

// string encoder 
pub fn str_to_bvec<N>(string: str<N>) -> BoundedVec<u8, 90> {
    let mut out: BoundedVec<u8, 90> = BoundedVec::new();
    let string_bytes = string.as_bytes();
    for i in 0..N {
        out.push(string_bytes[i]);
    }
    out
}

#[test]
fn test_single_decode() {
    let mut data: BoundedVec<u8, 90> = str_to_bvec("bc1q3x5ecspn9jjp9ah33000lcnrx35s0kq7f8tyan");
    let witness = segwit_decode(data);
    // pubkeyhash: 
    // 0x89a99c40332ca412f6f18bdeffe263346907d81e
    assert(
        witness == witness_builder(
            0,
            [137, 169, 156, 64, 51, 44, 164, 18, 246, 241, 139, 222, 255, 226, 99, 52, 105, 7, 216, 30]
        )
    );
}

#[test]
fn valid_addresses() {
    let data = [
        str_to_bvec("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"),
        str_to_bvec("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"),
        str_to_bvec("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"),
        str_to_bvec("BC1SW50QGDZ25J"),
        str_to_bvec("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"),
        str_to_bvec("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c")
    ];
    let data_witness = [
        witness_builder(
            0,
            [117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214]
        ),
        witness_builder(
            0,
            [
            24, 99, 20, 60, 20, 197, 22, 104, 4, 189, 25, 32, 51, 86, 218, 19, 108, 152, 86, 120, 205, 77, 39, 161, 184, 198, 50, 150, 4, 144, 50, 98
        ]
        ),
        witness_builder(
            1,
            [
            117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214, 117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67, 59, 214
        ]
        ),

        witness_builder(16, [117, 30]),
        witness_builder(
            2,
            [117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35]
        ),
        witness_builder(
            1,
            [
            0, 0, 0, 196, 165, 202, 212, 98, 33, 178, 161, 135, 144, 94, 82, 102, 54, 43, 153, 213, 233, 28, 108, 226, 77, 22, 93, 171, 147, 232, 100, 51
        ]
        )
    ];

    for i in 0..data.len() {
        let witness = segwit_decode(data[i]);
        assert(witness == data_witness[i]);
    }
}

