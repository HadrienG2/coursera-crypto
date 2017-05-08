//! This module is an implementation of the SHA-256 hashing algorithm

use padding::PaddingScheme;
use padding::merkle_damgard::MDPadding512u32;


// Logical functions used by SHA-256 (function names taken from NIST standard)
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}
//
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}
//
fn capital_sigma_0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
//
fn capital_sigma_1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
//
fn sigma_0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
//
fn sigma_1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}


// Constants used by SHA-256
const K: [u32; 64] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];


// Initial hash value of SHA-256
const H_0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];


// Compute the SHA-256 hash of any message
pub fn sha_256(message: &[u8]) -> [u8; 256/8] {
    // Set the initial hash value
    let mut hash = H_0;

    // Parse and pad the message into 512-bit blocks of 32-bit words, then
    // iterate over the resulting message blocks
    for message_block in MDPadding512u32::new(message) {
        // Prepare the message schedule
        let mut w = [0; 64];
        w[0..16].copy_from_slice(&message_block[..]);
        for t in 16..64 {
            w[t] = sigma_1(w[t-2]).wrapping_add(w[t-7])
                                  .wrapping_add(sigma_0(w[t-15]))
                                  .wrapping_add(w[t-16]);
        }

        // Initialize the eight working variables from the previous hash value
        let (mut a, mut b, mut c, mut d) = (hash[0], hash[1], hash[2], hash[3]);
        let (mut e, mut f, mut g, mut h) = (hash[4], hash[5], hash[6], hash[7]);

        // Compute the hash increment
        for t in 0..64 {
            let t_1 = h.wrapping_add(capital_sigma_1(e))
                       .wrapping_add(ch(e, f, g))
                       .wrapping_add(K[t])
                       .wrapping_add(w[t]);
            let t_2 = capital_sigma_0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t_1);
            d = c;
            c = b;
            b = a;
            a = t_1.wrapping_add(t_2);
        }

        // Update the hash value
        hash[0] = hash[0].wrapping_add(a);
        hash[1] = hash[1].wrapping_add(b);
        hash[2] = hash[2].wrapping_add(c);
        hash[3] = hash[3].wrapping_add(d);
        hash[4] = hash[4].wrapping_add(e);
        hash[5] = hash[5].wrapping_add(f);
        hash[6] = hash[6].wrapping_add(g);
        hash[7] = hash[7].wrapping_add(h);
    }

    // Output the final hash value
    let mut result = [0u8; 256/8];
    for (input, outputs) in hash.iter().zip(result.chunks_mut(4)) {
        outputs.copy_from_slice(&[(*input >> 24) as u8,
                                  ((*input >> 16) & 0xff) as u8,
                                  ((*input >> 8) & 0xff) as u8,
                                  (*input & 0xff) as u8]);
    };
    result
}


#[cfg(test)]
mod tests {
    use hash::sha_256::sha_256;

    #[test]
    fn one_block_message_sample() {
        let input = [0x61, 0x62, 0x63];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                          0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                          0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                          0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad]);
    }

    #[test]
    fn two_block_message_sample() {
        let input = [0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65,
                     0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
                     0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69,
                     0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
                     0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
                     0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
                     0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                          0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                          0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                          0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1]);
    }

    #[test]
    fn one_byte() {
        let input = [0xbd];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x68, 0x32, 0x57, 0x20, 0xaa, 0xbd, 0x7c, 0x82,
                          0xf3, 0x0f, 0x55, 0x4b, 0x31, 0x3d, 0x05, 0x70,
                          0xc9, 0x5a, 0xcc, 0xbb, 0x7d, 0xc4, 0xb5, 0xaa,
                          0xe1, 0x12, 0x04, 0xc0, 0x8f, 0xfe, 0x73, 0x2b]);
    }

    #[test]
    fn four_bytes() {
        let input = [0xc9, 0x8c, 0x8e, 0x55];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x7a, 0xbc, 0x22, 0xc0, 0xae, 0x5a, 0xf2, 0x6c,
                          0xe9, 0x3d, 0xbb, 0x94, 0x43, 0x3a, 0x0e, 0x0b,
                          0x2e, 0x11, 0x9d, 0x01, 0x4f, 0x8e, 0x7f, 0x65,
                          0xbd, 0x56, 0xc6, 0x1c, 0xcc, 0xcd, 0x95, 0x04]);
    }

    #[test]
    fn fifty_five_zeros() {
        let input = [0; 55];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x02, 0x77, 0x94, 0x66, 0xcd, 0xec, 0x16, 0x38,
                          0x11, 0xd0, 0x78, 0x81, 0x5c, 0x63, 0x3f, 0x21,
                          0x90, 0x14, 0x13, 0x08, 0x14, 0x49, 0x00, 0x2f,
                          0x24, 0xaa, 0x3e, 0x80, 0xf0, 0xb8, 0x8e, 0xf7]);
    }

    #[test]
    fn fifty_six_zeros() {
        let input = [0; 56];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xd4, 0x81, 0x7a, 0xa5, 0x49, 0x76, 0x28, 0xe7,
                          0xc7, 0x7e, 0x6b, 0x60, 0x61, 0x07, 0x04, 0x2b,
                          0xbb, 0xa3, 0x13, 0x08, 0x88, 0xc5, 0xf4, 0x7a,
                          0x37, 0x5e, 0x61, 0x79, 0xbe, 0x78, 0x9f, 0xbb]);
    }

    #[test]
    fn fifty_seven_zeros() {
        let input = [0; 57];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x65, 0xa1, 0x6c, 0xb7, 0x86, 0x13, 0x35, 0xd5,
                          0xac, 0xe3, 0xc6, 0x07, 0x18, 0xb5, 0x05, 0x2e,
                          0x44, 0x66, 0x07, 0x26, 0xda, 0x4c, 0xd1, 0x3b,
                          0xb7, 0x45, 0x38, 0x1b, 0x23, 0x5a, 0x17, 0x85]);
    }

    #[test]
    fn sixty_four_zeros() {
        let input = [0; 64];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xf5, 0xa5, 0xfd, 0x42, 0xd1, 0x6a, 0x20, 0x30,
                          0x27, 0x98, 0xef, 0x6e, 0xd3, 0x09, 0x97, 0x9b,
                          0x43, 0x00, 0x3d, 0x23, 0x20, 0xd9, 0xf0, 0xe8,
                          0xea, 0x98, 0x31, 0xa9, 0x27, 0x59, 0xfb, 0x4b]);
    }

    #[test]
    fn a_thousand_zeros() {
        let input = [0; 1000];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x54, 0x1b, 0x3e, 0x9d, 0xaa, 0x09, 0xb2, 0x0b,
                          0xf8, 0x5f, 0xa2, 0x73, 0xe5, 0xcb, 0xd3, 0xe8,
                          0x01, 0x85, 0xaa, 0x4e, 0xc2, 0x98, 0xe7, 0x65,
                          0xdb, 0x87, 0x74, 0x2b, 0x70, 0x13, 0x8a, 0x53]);
    }

    #[test]
    fn a_thousand_41() {
        let input = [0x41; 1000];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xc2, 0xe6, 0x86, 0x82, 0x34, 0x89, 0xce, 0xd2,
                          0x01, 0x7f, 0x60, 0x59, 0xb8, 0xb2, 0x39, 0x31,
                          0x8b, 0x63, 0x64, 0xf6, 0xdc, 0xd8, 0x35, 0xd0,
                          0xa5, 0x19, 0x10, 0x5a, 0x1e, 0xad, 0xd6, 0xe4]);
    }

    #[test]
    fn a_thousand_and_five_55() {
        let input = [0x55; 1005];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xf4, 0xd6, 0x2d, 0xde, 0xc0, 0xf3, 0xdd, 0x90,
                          0xea, 0x13, 0x80, 0xfa, 0x16, 0xa5, 0xff, 0x8d,
                          0xc4, 0xc5, 0x4b, 0x21, 0x74, 0x06, 0x50, 0xf2,
                          0x4a, 0xfc, 0x41, 0x20, 0x90, 0x35, 0x52, 0xb0]);
    }

    #[test]
    fn a_million_zeros() {
        let input = vec![0; 1_000_000];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xd2, 0x97, 0x51, 0xf2, 0x64, 0x9b, 0x32, 0xff,
                          0x57, 0x2b, 0x5e, 0x0a, 0x9f, 0x54, 0x1e, 0xa6,
                          0x60, 0xa5, 0x0f, 0x94, 0xff, 0x0b, 0xee, 0xdf,
                          0xb0, 0xb6, 0x92, 0xb9, 0x24, 0xcc, 0x80, 0x25]);
    }

    // The following tests are highly ressource intensive and should only be
    // run in release mode, which is why they are ignored by default.
    #[test]
    #[ignore]
    fn half_a_billion_5a() {
        let input = vec![0x5a; 0x2000_0000];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x15, 0xa1, 0x86, 0x8c, 0x12, 0xcc, 0x53, 0x95,
                          0x1e, 0x18, 0x23, 0x44, 0x27, 0x74, 0x47, 0xcd,
                          0x09, 0x79, 0x53, 0x6b, 0xad, 0xcc, 0x51, 0x2a,
                          0xd2, 0x4c, 0x67, 0xe9, 0xb2, 0xd4, 0xf3, 0xdd]);
    }
    //
    #[test]
    #[ignore]
    fn a_billion_zeros() {
        let input = vec![0; 0x4100_0000];
        let hash = sha_256(&input);
        assert_eq!(hash, [0x46, 0x1c, 0x19, 0xa9, 0x3b, 0xd4, 0x34, 0x4f,
                          0x92, 0x15, 0xf5, 0xec, 0x64, 0x35, 0x70, 0x90,
                          0x34, 0x2b, 0xc6, 0x6b, 0x15, 0xa1, 0x48, 0x31,
                          0x7d, 0x27, 0x6e, 0x31, 0xcb, 0xc2, 0x0b, 0x53]);
    }
    //
    #[test]
    #[ignore]
    fn two_billions_42() {
        let input = vec![0x42; 0x6000_003e];
        let hash = sha_256(&input);
        assert_eq!(hash, [0xc2, 0x3c, 0xe8, 0xa7, 0x89, 0x5f, 0x4b, 0x21,
                          0xec, 0x0d, 0xaf, 0x37, 0x92, 0x0a, 0xc0, 0xa2,
                          0x62, 0xa2, 0x20, 0x04, 0x5a, 0x03, 0xeb, 0x2d,
                          0xfe, 0xd4, 0x8e, 0xf9, 0xb0, 0x5a, 0xab, 0xea]);
    }
}
