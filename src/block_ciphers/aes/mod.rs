//! This module is an implementation of the AES block cipher

mod gf_byte;
mod gf_word;
mod state;

use block_ciphers::Block128u8;
use block_ciphers::aes::gf_word::GFWord;
use block_ciphers::aes::state::{N_B, State};


// ### BASIC DATA STRUCTURES ###

// The inputs and outputs of AES are blocks of 128 bits
pub type Input = Block128u8;
pub type Output = Block128u8;

// An AES key may be 128, 192 or 256 bits long
pub type Key128 = [u8; 128/8];
pub type Key192 = [u8; 192/8];
pub type Key256 = [u8; 256/8];

// AES also uses byte substitution tables, aka S-boxes
type SBox = [u8; 256];


// ### S-BOXES USED BY AES ###

// The following S-box is used for encryption and key expansion. It was
// constructed by taking the multiplicative inverse of each byte in GF(2^8),
// mapping 0x00 to itself, then applying an affine transformation to the result.
const ENC_SBOX: SBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
                        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
                        0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
                        0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
                        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                        0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
                        0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
                        0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
                        0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
                        0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
                        0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
                        0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
                        0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
                        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
                        0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
                        0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];

// This is the inverse of the encryption S-box, which can be used for
// decryption. It can be obtained by applying the inverse of the affine
// transformation, followed by taking the multiplicative inverse of the byte in
// GF(2^8). But personally, I just brute-forced it from the encryption S-box.
const DEC_SBOX: SBox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 
                        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 
                        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 
                        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 
                        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 
                        0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 
                        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 
                        0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 
                        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 
                        0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 
                        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 
                        0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 
                        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 
                        0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 
                        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 
                        0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 
                        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 
                        0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 
                        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 
                        0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 
                        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 
                        0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 
                        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 
                        0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 
                        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 
                        0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 
                        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 
                        0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 
                        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 
                        0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 
                        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 
                        0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];


// ### KEY EXPANSION ###

// AES keys are expanded into a set of round keys. The amount of encryption
// rounds Nr, which determins the amount of round keys, depends on the key size.
type RoundKeys = [GFWord];
pub type RoundKeys128 = [GFWord; N_B*(10+1)];  // Nr = 10 for 128-bit keys
pub type RoundKeys192 = [GFWord; N_B*(12+1)];  // Nr = 12 for 192-bit keys
pub type RoundKeys256 = [GFWord; N_B*(14+1)];  // Nr = 14 for 256-bit keys

// Here is a generic key expansion routine. It works by taking up the slice of
// keys and writing into the slice of round keys.
fn key_expansion(key: &[u8], w: &mut RoundKeys) {
    // Retrieve Nk from the length of the key slice
    assert_eq!(key.len() % 4, 0);
    let n_k = key.len() / 4;

    // Determine Nr (for AES, Nr = Nk + 6 should always hold)
    let n_r = n_k + 6;
    assert_eq!(w.len(), N_B*(n_r+1));

    // Compute the round constants. Ideally, these should be global constants,
    // but Rust does not allow for this yet...
    let r_con = [GFWord::zero(),             GFWord::new(0x01, 0, 0, 0),
                 GFWord::new(0x02, 0, 0, 0), GFWord::new(0x04, 0, 0, 0),
                 GFWord::new(0x08, 0, 0, 0), GFWord::new(0x10, 0, 0, 0),
                 GFWord::new(0x20, 0, 0, 0), GFWord::new(0x40, 0, 0, 0),
                 GFWord::new(0x80, 0, 0, 0), GFWord::new(0x1b, 0, 0, 0),
                 GFWord::new(0x36, 0, 0, 0)];

    // Initialize the key expansion recursion with the key
    for i in 0..n_k {
        w[i] = GFWord::new(key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]);
    }

    // Expand the initial key into the full set of round keys
    for i in n_k..N_B*(n_r+1) {
        let mut temp = w[i-1];
        if i % n_k == 0 {
            temp = temp.rot_word().sub_word() + r_con[i/n_k];
        } else if (n_k > 6) && (i % n_k == 4) {
            temp = temp.sub_word();
        }
        w[i] = w[i-n_k] + temp;
    }
}

// From the routine above, we can build the 128-bit key expansion routine...
pub fn key_expansion_128(key: &Key128) -> RoundKeys128 {
    let mut result = [GFWord::zero(); N_B*(10+1)];
    key_expansion(&key[..], &mut result[..]);
    result
}

// ...the 192-bit key expansion routine...
pub fn key_expansion_192(key: &Key192) -> RoundKeys192 {
    let mut result = [GFWord::zero(); N_B*(12+1)];
    key_expansion(&key[..], &mut result[..]);
    result
}

// ...and the 256-bit key expansion routine
pub fn key_expansion_256(key: &Key256) -> RoundKeys256 {
    let mut result = [GFWord::zero(); N_B*(14+1)];
    key_expansion(&key[..], &mut result[..]);
    result
}


// ### ENCRYPTION AND DECRYPTION ###

// The AES cipher
pub fn cipher(input: &Input, round_keys: &RoundKeys) -> Output {
    // Make sure that the amount of round keys is sensical
    assert_eq!(round_keys.len() % N_B, 0);
    assert!(round_keys.len() > N_B);
    let n_r = round_keys.len()/N_B - 1;

    // Initialize the AES state from the input data
    let mut state = State::from(input);

    // XOR it with the initial round key
    state.add_round_key(&round_keys[0..N_B]);

    // Perform the following encryption rounds
    for round in 1..n_r {
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_keys[(round*N_B)..((round+1)*N_B)]);
    }

    // Apply the final transformations
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_keys[(n_r*N_B)..(n_r+1)*N_B]);

    // Extract the final state and return it as our output
    state.into()
}

// Straightforward inverse cipher
pub fn inv_cipher(input: &Input, round_keys: &RoundKeys) -> Output {
    // Make sure that the amount of round keys is sensical
    assert_eq!(round_keys.len() % N_B, 0);
    assert!(round_keys.len() > N_B);
    let n_r = round_keys.len()/N_B - 1;

    // Initialize the AES state from the input data
    let mut state = State::from(input);

    // XOR it with the final round key
    state.add_round_key(&round_keys[(n_r*N_B)..(n_r+1)*N_B]);

    // Perform the encryption rounds in reverse order
    for round in (1..n_r).rev() {
        state.inv_shift_rows();
        state.inv_sub_bytes();
        state.add_round_key(&round_keys[(round*N_B)..((round+1)*N_B)]);
        state.inv_mix_columns();
    }

    // Apply the final transformations
    state.inv_shift_rows();
    state.inv_sub_bytes();
    state.add_round_key(&round_keys[0..N_B]);

    // Extract the final state and return it as our output
    state.into()
}


#[cfg(test)]
mod tests {
    use block_ciphers::aes;
    use block_ciphers::aes::gf_word::GFWord;

    // Check that 128-bit key expansion from appendix A works as expected
    #[test]
    fn key_expansion_128() {
        let actual = aes::key_expansion_128(&[0x2b, 0x7e, 0x15, 0x16,
                                              0x28, 0xae, 0xd2, 0xa6,
                                              0xab, 0xf7, 0x15, 0x88,
                                              0x09, 0xcf, 0x4f, 0x3c]);
        let expected = [GFWord::from(0x2b7e1516), GFWord::from(0x28aed2a6),
                        GFWord::from(0xabf71588), GFWord::from(0x09cf4f3c),
                        GFWord::from(0xa0fafe17), GFWord::from(0x88542cb1),
                        GFWord::from(0x23a33939), GFWord::from(0x2a6c7605),
                        GFWord::from(0xf2c295f2), GFWord::from(0x7a96b943),
                        GFWord::from(0x5935807a), GFWord::from(0x7359f67f),
                        GFWord::from(0x3d80477d), GFWord::from(0x4716fe3e),
                        GFWord::from(0x1e237e44), GFWord::from(0x6d7a883b),
                        GFWord::from(0xef44a541), GFWord::from(0xa8525b7f),
                        GFWord::from(0xb671253b), GFWord::from(0xdb0bad00),
                        GFWord::from(0xd4d1c6f8), GFWord::from(0x7c839d87),
                        GFWord::from(0xcaf2b8bc), GFWord::from(0x11f915bc),
                        GFWord::from(0x6d88a37a), GFWord::from(0x110b3efd),
                        GFWord::from(0xdbf98641), GFWord::from(0xca0093fd),
                        GFWord::from(0x4e54f70e), GFWord::from(0x5f5fc9f3),
                        GFWord::from(0x84a64fb2), GFWord::from(0x4ea6dc4f),
                        GFWord::from(0xead27321), GFWord::from(0xb58dbad2),
                        GFWord::from(0x312bf560), GFWord::from(0x7f8d292f),
                        GFWord::from(0xac7766f3), GFWord::from(0x19fadc21),
                        GFWord::from(0x28d12941), GFWord::from(0x575c006e),
                        GFWord::from(0xd014f9a8), GFWord::from(0xc9ee2589),
                        GFWord::from(0xe13f0cc8), GFWord::from(0xb6630ca6)];
        assert_eq!(&actual[..], &expected[..]);
    }

    // Check that 192-bit key expansion from appendix A works as expected
    #[test]
    fn key_expansion_192() {
        let actual = aes::key_expansion_192(&[0x8e, 0x73, 0xb0, 0xf7,
                                              0xda, 0x0e, 0x64, 0x52,
                                              0xc8, 0x10, 0xf3, 0x2b,
                                              0x80, 0x90, 0x79, 0xe5,
                                              0x62, 0xf8, 0xea, 0xd2,
                                              0x52, 0x2c, 0x6b, 0x7b]);
        let expected = [GFWord::from(0x8e73b0f7), GFWord::from(0xda0e6452),
                        GFWord::from(0xc810f32b), GFWord::from(0x809079e5),
                        GFWord::from(0x62f8ead2), GFWord::from(0x522c6b7b),
                        GFWord::from(0xfe0c91f7), GFWord::from(0x2402f5a5),
                        GFWord::from(0xec12068e), GFWord::from(0x6c827f6b),
                        GFWord::from(0x0e7a95b9), GFWord::from(0x5c56fec2),
                        GFWord::from(0x4db7b4bd), GFWord::from(0x69b54118),
                        GFWord::from(0x85a74796), GFWord::from(0xe92538fd),
                        GFWord::from(0xe75fad44), GFWord::from(0xbb095386),
                        GFWord::from(0x485af057), GFWord::from(0x21efb14f),
                        GFWord::from(0xa448f6d9), GFWord::from(0x4d6dce24),
                        GFWord::from(0xaa326360), GFWord::from(0x113b30e6),
                        GFWord::from(0xa25e7ed5), GFWord::from(0x83b1cf9a),
                        GFWord::from(0x27f93943), GFWord::from(0x6a94f767),
                        GFWord::from(0xc0a69407), GFWord::from(0xd19da4e1),
                        GFWord::from(0xec1786eb), GFWord::from(0x6fa64971),
                        GFWord::from(0x485f7032), GFWord::from(0x22cb8755),
                        GFWord::from(0xe26d1352), GFWord::from(0x33f0b7b3),
                        GFWord::from(0x40beeb28), GFWord::from(0x2f18a259),
                        GFWord::from(0x6747d26b), GFWord::from(0x458c553e),
                        GFWord::from(0xa7e1466c), GFWord::from(0x9411f1df),
                        GFWord::from(0x821f750a), GFWord::from(0xad07d753),
                        GFWord::from(0xca400538), GFWord::from(0x8fcc5006),
                        GFWord::from(0x282d166a), GFWord::from(0xbc3ce7b5),
                        GFWord::from(0xe98ba06f), GFWord::from(0x448c773c),
                        GFWord::from(0x8ecc7204), GFWord::from(0x01002202)];
        assert_eq!(&actual[..], &expected[..]);
    }

    // Check that 256-bit key expansion from appendix A works as expected
    #[test]
    fn key_expansion_256() {
        let actual = aes::key_expansion_256(&[0x60, 0x3d, 0xeb, 0x10,
                                              0x15, 0xca, 0x71, 0xbe,
                                              0x2b, 0x73, 0xae, 0xf0,
                                              0x85, 0x7d, 0x77, 0x81,
                                              0x1f, 0x35, 0x2c, 0x07,
                                              0x3b, 0x61, 0x08, 0xd7,
                                              0x2d, 0x98, 0x10, 0xa3,
                                              0x09, 0x14, 0xdf, 0xf4]);
        let expected = [GFWord::from(0x603deb10), GFWord::from(0x15ca71be),
                        GFWord::from(0x2b73aef0), GFWord::from(0x857d7781),
                        GFWord::from(0x1f352c07), GFWord::from(0x3b6108d7),
                        GFWord::from(0x2d9810a3), GFWord::from(0x0914dff4),
                        GFWord::from(0x9ba35411), GFWord::from(0x8e6925af),
                        GFWord::from(0xa51a8b5f), GFWord::from(0x2067fcde),
                        GFWord::from(0xa8b09c1a), GFWord::from(0x93d194cd),
                        GFWord::from(0xbe49846e), GFWord::from(0xb75d5b9a),
                        GFWord::from(0xd59aecb8), GFWord::from(0x5bf3c917),
                        GFWord::from(0xfee94248), GFWord::from(0xde8ebe96),
                        GFWord::from(0xb5a9328a), GFWord::from(0x2678a647),
                        GFWord::from(0x98312229), GFWord::from(0x2f6c79b3),
                        GFWord::from(0x812c81ad), GFWord::from(0xdadf48ba),
                        GFWord::from(0x24360af2), GFWord::from(0xfab8b464),
                        GFWord::from(0x98c5bfc9), GFWord::from(0xbebd198e),
                        GFWord::from(0x268c3ba7), GFWord::from(0x09e04214),
                        GFWord::from(0x68007bac), GFWord::from(0xb2df3316),
                        GFWord::from(0x96e939e4), GFWord::from(0x6c518d80),
                        GFWord::from(0xc814e204), GFWord::from(0x76a9fb8a),
                        GFWord::from(0x5025c02d), GFWord::from(0x59c58239),
                        GFWord::from(0xde136967), GFWord::from(0x6ccc5a71),
                        GFWord::from(0xfa256395), GFWord::from(0x9674ee15),
                        GFWord::from(0x5886ca5d), GFWord::from(0x2e2f31d7),
                        GFWord::from(0x7e0af1fa), GFWord::from(0x27cf73c3),
                        GFWord::from(0x749c47ab), GFWord::from(0x18501dda),
                        GFWord::from(0xe2757e4f), GFWord::from(0x7401905a),
                        GFWord::from(0xcafaaae3), GFWord::from(0xe4d59b34),
                        GFWord::from(0x9adf6ace), GFWord::from(0xbd10190d),
                        GFWord::from(0xfe4890d1), GFWord::from(0xe6188d0b),
                        GFWord::from(0x046df344), GFWord::from(0x706c631e)];
        assert_eq!(&actual[..], &expected[..]);
    }

    // Check that the 128-bit cipher example from appendix B works as expected
    #[test]
    fn cipher_example() {
        let output = 
            aes::cipher(&[0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                          0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34],
                        &aes::key_expansion_128(&[0x2b, 0x7e, 0x15, 0x16,
                                                  0x28, 0xae, 0xd2, 0xa6,
                                                  0xab, 0xf7, 0x15, 0x88,
                                                  0x09, 0xcf, 0x4f, 0x3c]));
        assert_eq!(output, [0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
                            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32]);
    }

    // Check that the standard AES test vectors from appendix C work as expected
    #[test]
    fn example_vectors() {
        // The plain text is always the same
        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                         0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // 128-bit cipher test
        let key_128 = aes::key_expansion_128(&[0x00, 0x01, 0x02, 0x03,
                                               0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b,
                                               0x0c, 0x0d, 0x0e, 0x0f]);
        let cipher_128 = aes::cipher(&plaintext, &key_128);
        assert_eq!(cipher_128,
                   [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]);
        assert_eq!(aes::inv_cipher(&cipher_128, &key_128), plaintext);

        // 192-bit cipher test
        let key_192 = aes::key_expansion_192(&[0x00, 0x01, 0x02, 0x03,
                                               0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b,
                                               0x0c, 0x0d, 0x0e, 0x0f,
                                               0x10, 0x11, 0x12, 0x13,
                                               0x14, 0x15, 0x16, 0x17]);
        let cipher_192 = aes::cipher(&plaintext, &key_192);
        assert_eq!(cipher_192,
                   [0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0,
                    0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91]);
        assert_eq!(aes::inv_cipher(&cipher_192, &key_192), plaintext);

        // 256-bit cipher test
        let key_256 = aes::key_expansion_256(&[0x00, 0x01, 0x02, 0x03,
                                               0x04, 0x05, 0x06, 0x07,
                                               0x08, 0x09, 0x0a, 0x0b,
                                               0x0c, 0x0d, 0x0e, 0x0f,
                                               0x10, 0x11, 0x12, 0x13,
                                               0x14, 0x15, 0x16, 0x17,
                                               0x18, 0x19, 0x1a, 0x1b,
                                               0x1c, 0x1d, 0x1e, 0x1f]);
        let cipher_256 = aes::cipher(&plaintext, &key_256);
        assert_eq!(cipher_256,
                   [0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
                    0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89]);
        assert_eq!(aes::inv_cipher(&cipher_256, &key_256), plaintext);
    }
}
