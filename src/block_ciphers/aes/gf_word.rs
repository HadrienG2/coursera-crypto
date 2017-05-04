//! This module helps manipulating 32-bit words as polynomials whose
//! coefficients are finite field elements

use block_ciphers::aes::{ENC_SBOX, SBox};
use block_ciphers::aes::gf_byte::GFByte;
use std::fmt;
use std::ops::{Add, Index, IndexMut, Mul};


/// 4-byte words are sometimes interpreted by AES as 4-term polynomials with
/// coefficients that are finite field elements (i.e. bytes).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GFWord {
    bytes: [GFByte; 4],
}

/// The addition operator simply maps to addition of polynomial coefficients
impl Add for GFWord {
    type Output = GFWord;

    fn add(self, rhs: Self) -> Self {
        Self {
            bytes: [self.bytes[0] + rhs.bytes[0],
                    self.bytes[1] + rhs.bytes[1],
                    self.bytes[2] + rhs.bytes[2],
                    self.bytes[3] + rhs.bytes[3]],
        }
    }
}

/// Multiplication is again defined as multiplication of polynomials modulo an
/// irreducible polynomial, however this time the polynomial is x^4 + 1.
impl Mul for GFWord {
    type Output = GFWord;

    fn mul(self, rhs: Self) -> Self {
        // If we denote the input polynomials a & b as in the AES spec...
        let (a, b) = (&self.bytes, &rhs.bytes);

        // ...then we can reuse as-is the spec-provided multiplication result
        Self {
            bytes: [a[0]*b[0] + a[3]*b[1] + a[2]*b[2] + a[1]*b[3],
                    a[1]*b[0] + a[0]*b[1] + a[3]*b[2] + a[2]*b[3],
                    a[2]*b[0] + a[1]*b[1] + a[0]*b[2] + a[3]*b[3],
                    a[3]*b[0] + a[2]*b[1] + a[1]*b[2] + a[0]*b[3]],
        }
    }
}

/// Words are displayed as in the AES standard
impl fmt::Display for GFWord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.bytes.iter() {
            write!(f, "{}", *byte)?;
        }
        Ok(())
    }
}

/// Explicit conversions from 32-bit words are provided
impl From<u32> for GFWord {
    fn from(word: u32) -> Self {
        Self::new(((word & 0xff000000) / 0x1000000) as u8,
                  ((word & 0xff0000) / 0x10000) as u8,
                  ((word & 0xff00) / 0x100) as u8,
                  (word & 0xff) as u8)
    }
}

/// Words may be indexed in order to access the inner bytes, using the same
/// index convention as AES (byte 0 is the first byte in row order)
impl Index<usize> for GFWord {
    type Output = GFByte;

    fn index(&self, index: usize) -> &GFByte {
        &self.bytes[index]
    }
}
//
impl IndexMut<usize> for GFWord {
    fn index_mut(&mut self, index: usize) -> &mut GFByte {
        &mut self.bytes[index]
    }
}

/// In addition, we provide some extra specific crypto primitives on words
impl GFWord {
    // A word is built from 4 bytes...
    pub fn new(b0: u8, b1: u8, b2: u8, b3: u8) -> Self {
        Self {
            bytes: [GFByte::from(b0),
                    GFByte::from(b1),
                    GFByte::from(b2),
                    GFByte::from(b3)],
        }
    }

    // We provide an easy way to zero-initialize a word
    pub fn zero() -> Self {
        Self::new(0, 0, 0, 0)
    }

    // Applying an S-box to a word applies it to the inner bytes
    pub fn apply_s_box(&mut self, sb: &SBox) {
        for byte in self.bytes.iter_mut() {
            byte.apply_s_box(sb);
        }
    }

    // The RotWord function performs a cyclic permutation on the bytes of a word
    pub fn rot_word(&self) -> Self {
        Self {
            bytes: [self.bytes[1],
                    self.bytes[2],
                    self.bytes[3],
                    self.bytes[0]],
        }
    }

    // The SubWord function applies the encryption S-box to the bytes in a word
    pub fn sub_word(&self) -> Self {
        let mut result = self.clone();
        result.apply_s_box(&ENC_SBOX);
        result
    }
}


#[cfg(test)]
mod tests {
    use aes::gf_word::GFWord;

    // Test that GFWord multiplication works as expected by the AES spec
    #[test]
    fn mul() {
        let a = GFWord::new(0x02, 0x01, 0x01, 0x03);
        let inv_a = GFWord::new(0x0e, 0x09, 0x0d, 0x0b);
        assert_eq!(a * inv_a, GFWord::new(1, 0, 0, 0));
        let word = GFWord::new(0, 1, 2, 3);
        let rot = GFWord::new(0, 0, 0, 1);
        assert_eq!(word * rot, GFWord::new(1, 2, 3, 0));
    }
}
