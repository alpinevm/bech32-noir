use dep::std;

/// Grouping structure for the human-readable part and the data part
/// of decoded Bech32 string.
struct Bech32 {
    /// Human-readable part
	// usually just 2 chars for btc addresses but staying true to docs
    hrp: BoundedVec<u8, 80>,
    /// Data payload, actual size : 90 - len(hrp) - 1?, defaulting to safe max size
    data: BoundedVec<u8, 90>,
	spec: u32
}

global ENCODING_BECH32: u32 = 1;
global ENCODING_BECH32M: u32 = 2;

global BECH32M_CONST: u32 = 0x2bc830a3;

// Human-readable part and data part separator
global SEP: str<1> = "1";
global SEP_ASCII_CODE: u8 = 49;

// Encoding character set. Maps data value -> char
global CHARSET: [str<1>; 32] = [
    "q","p","z","r","y","9","x","8",
    "g","f","2","t","v","d","w","0",
    "s","3","j","n","5","4","k","h",
    "c","e","6","m","u","a","7","l"
];

// Reverse character set. Maps ASCII byte -> CHARSET index on [0,31]
global CHARSET_REV: [i8; 128] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
];

// Generator coefficients
global GEN: [Field; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

fn create_checksum(hrp: BoundedVec<u8, 80>, data: BoundedVec<u8, 90>) -> BoundedVec<u8,6> {
    let mut values = hrp_expand(hrp);
    // extend the array to fit all data needed
    let mut pmod_input: BoundedVec<u8, 256> = BoundedVec::new();
    pmod_input.extend_from_bounded_vec(values);
    pmod_input.extend_from_bounded_vec(data);
    // Pad with 6 zeros
    pmod_input.extend_from_array([0 as u8; 6]);
    let plm: u32 = polymod(pmod_input) ^ 1;
    let mut checksum: BoundedVec<u8, 6> = BoundedVec::new();
    for p in 0..6 {
        checksum.push(((plm >> 5 * (5 - p)) & 0x1f) as u8);
    }
    checksum
}

fn verify_checksum(hrp: BoundedVec<u8, 80>, data: BoundedVec<u8, 90>) -> Option<u32> {
    let mut exp = hrp_expand(hrp);
    exp.extend_from_bounded_vec(data);
    let mut pmod_input: BoundedVec<u8, 256> = BoundedVec::new();
    pmod_input.extend_from_bounded_vec(exp);
    let pmod_const = polymod(pmod_input);
    let mut out: Option<u32> = Option::none();
    if pmod_const == ENCODING_BECH32 {
        out = Option::some(ENCODING_BECH32 as u32);
    } else if pmod_const == BECH32M_CONST {
        out = Option::some(ENCODING_BECH32M );
    }
    out
}

// length comes from max hrp
fn hrp_expand(hrp: BoundedVec<u8, 80>) -> BoundedVec<u8, 160> {
    let mut v: BoundedVec<u8, 160> = BoundedVec::new();
    for i in 0..hrp.max_len() {
        if i < hrp.len() {
            let b = hrp.get(i);
            v.push(b >> 5);
        }
    }
    v.push(0);
    for i in 0..hrp.max_len() {
        if i < hrp.len() {
            let b = hrp.get(i);
            v.push(b & 0x1f);
        }
    }
    v
}

// max length defined by:
// ( len(hrp) * 2 ) + len(data) + 6
fn polymod(values: BoundedVec<u8, 256>) -> u32 {
    let mut chk: u32 = 1;
    let mut b: u8 = 0;
    for i in 0..values.max_len() {
        if i < values.len() {
            let v = values.get(i);
            b = (chk >> 25) as u8;
            chk = (chk & 0x1ffffff) << 5 ^ (v as u32);
            for i in 0..5 {
                if (b >> i) & 1 == 1 {
                    chk ^= (GEN[i] as u32);
                }
            }
        }
    }
    chk
}

struct SepSplitOutput {
	valid: bool,
	bech_parts: Option<Bech32>
}

fn find_sep_and_split(s: BoundedVec<u8, 90>) -> SepSplitOutput {
    let mut output: SepSplitOutput = SepSplitOutput { bech_parts: Option::none(), valid: false };

    let mut pot_data: BoundedVec<u8, 90> = BoundedVec::new();
    let mut pot_hrp: BoundedVec<u8, 80> = BoundedVec::new();

    let mut aggregating_data = true;
    for i in 0..s.max_len() {
        if i < s.len() {
            if s.get(i) == SEP_ASCII_CODE {
                aggregating_data = false;
                output.valid = true;
            } else if aggregating_data {
                pot_hrp.push(s.get(i));
            } else {
                pot_data.push(s.get(i));
            }
        }
    }
    if output.valid {
        output.bech_parts = Option::some(Bech32 {
			hrp: pot_hrp,
			data: pot_data,
			// dummy data not actually used:
			spec: 0,
		});
    }
    output
}

impl Bech32 {

    // higher bits here is 8
    // lower bit count should implicitly be 5
    // output is overestimate
    pub fn convert_to_higher_bits(data: BoundedVec<u8, 90>) -> BoundedVec<u8, 90> {
        let from_bits: u32 = 5;
        let to_bits: u32 = 8;

        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        let mut ret: BoundedVec<u8, 90> = BoundedVec::new();
        let maxv: u32 = (1 << to_bits) - 1;

        for i in 0..data.max_len() {
            // the i != 0 check allows us to not have to allocate a new boundedvec with the first element removed
            if (i < data.len()) & (i != 0) {
                let value = data.get(i) as u32;
                assert(!((value >> from_bits) != 0), "bech32::InvalidValue");
                acc = (acc << from_bits) | value;
                bits += from_bits;
                // we can only do this b/c our accumulation will never need more than 1 op to decrease to limit (in ref this is a while loop)
                if bits >= to_bits {
                    // absolute value is needed to handle the fact noir will always execute these branches 
                    // maybe a more efficient way to do this
                    let bit_delta = (bits as i32) - (to_bits as i32);
                    let mask = (bit_delta >> (31 as i32)) * -1;
                    let abs_bit_delta = ((bit_delta ^ mask) - mask) as u32;
                    bits -= to_bits;
                    ret.push(((acc >> abs_bit_delta) & maxv) as u8);
                }
            }
        }
        assert(
            !(bits >= from_bits) | !(((acc << (to_bits - bits)) & maxv) != 0), "bech32::PaddingCheckFailed"
        );
        ret
    }
    /// Decode from a string with each character as an ascii code in a BoundedVec for efficiency
    pub fn decode(hash: BoundedVec<u8, 90>) -> Bech32 {
        // Ensure overall length is within bounds
        assert(!((hash.len() < 8) | (hash.len() > 90)), "bech32:InvalidLength");

        // Check for missing separator
        let sep_data = find_sep_and_split(hash);
        assert(sep_data.valid, "bech32::MissingSeperator");

        // Split at separator and check for two pieces
        let raw_hrp = sep_data.bech_parts.unwrap().hrp;
        let raw_data = sep_data.bech_parts.unwrap().data;
        assert(!((raw_hrp.len() < 1) | (raw_data.len() < 6)), "bech32::InvalidLength");

        let mut has_lower: bool = false;
        let mut has_upper: bool = false;
        let mut hrp_bytes: BoundedVec<u8, 80> = BoundedVec::new();

        for i in 0..raw_hrp.max_len() {
            if i < raw_hrp.len() {
                let b = raw_hrp.get(i);
                // Valid subset of ASCII
                assert(!((b < 33) | (b > 126)), "bec32::InvalidChar");

                let mut c = b;
                // Lowercase
                // char code for "a" and "z" respectively
                if (b >= 97) & (b <= 122) {
                    has_lower = true;
                }

                // Uppercase
                // char code for "A" and "Z" respectively
                if (b >= 65) & (b <= 90) {
                    has_upper = true;
                    // Convert to lowercase
                    // b + (ord('a') - ord('A'))
                    c = b + 32;
                }
                hrp_bytes.push(c);
            }
        }

        // Check data payload
        let mut data_bytes: BoundedVec<u8, 90> = BoundedVec::new();

        for i in 0..raw_data.max_len() {
            if i < raw_data.len() {
                let b = raw_data.get(i);
                // Aphanumeric only
                //((b >= ord('0') && b <= ord('9')) || (b >= ord('A') && b <= ord('Z')) || (b >= ord('a') && b <= ord('z')))
                assert(
                    (((b >= 48) & (b <= 57)) | ((b >= 65) & (b <= 90)) | ((b >= 97) & (b <= 122))), "bech32::InvalidChar"
                );

                // Excludes these characters: [1,b,i,o]
                // (b == ord('1') || b == ord('b') || b == ord('i') || b == ord('o'))
                assert(!((b == 49) | (b == 98) | (b == 105) | (b == 111)), "bech32::InvalidChar");

                // Lowercase
                // char code for "a" and "z" respectively
                if (b >= 97) & (b <= 122) {
                    has_lower = true;
                }

                let mut c = b;
                // Uppercase
                // char code for "A" and "Z" respectively
                if (b >= 65) & (b <= 90) {
                    has_upper = true;
                    // Convert to lowercase
                    // b + (ord('a') - ord('A'))
                    c = b + 32;
                }
                data_bytes.push(CHARSET_REV[c] as u8);
            }
        }

        // Ensure no mixed case
        assert(!(has_lower & has_upper), "bech32::MixedCase");

        // Ensure checksum
        let spec = verify_checksum(hrp_bytes, data_bytes);
        assert(spec.is_some(), "bech32::InvalidChecksum");

        // Remove checksum from data payload
        for _i in 0..6 {
            let _ = data_bytes.pop();
        }

        Bech32 { hrp: hrp_bytes, data: data_bytes, spec: spec.unwrap() }
    }
}

