//! This module helps manipulating bytes as elements of a finite field

use aes::SBox;
use std::fmt;
use std::ops::{Add, Mul};


/// The AES algorithm manipulates bytes, which are interpreted as elements of the
/// finite field GF(2^8) using a polynomial representation. For example, the
/// number 0b01100011 denotes the finite field element x^6 + x^5 + x + 1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GFByte {
    byte: u8,
}

/// The addition operator in the finite field maps to bitwise byte XOR
impl Add for GFByte {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self {
            byte: self.byte ^ rhs.byte,
        }
    }
}

/// The multiplication operator corresponds with the multiplication of
/// polynomials modulo an irreducible polynomial, which for the AES algorithm is
/// m(x) = x^8 + x^4 + x^3 + x + 1 (mapping to the 16-bit number 0x011b)
impl Mul for GFByte {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        // Let's extract the two input bytes
        let (b1, b2) = (self.byte, rhs.byte);

        // Multiplication by x (0b10) can be implemented as follows:
        //      - Check the high-order bit
        //      - Apply a left bitshift to the byte
        //      - Apply modulo as conditional subtraction (bitwise XOR) of 0x1b
        let mul_x = |b: u8| -> u8 {
            let high_order_bit = b >> 7;
            let shifted_b = b << 1;
            let conditional_sub = high_order_bit * 0x1b;
            shifted_b ^ conditional_sub
        };

        // Multiplication by an arbitrary binary number can be iterativeively
        // implemented in terms of additions and multiplications by 1 and x.
        let mut accumulator = 0;
        let mut remainder = b2;
        let mut multiplier = b1;
        for _ in 0..8 {
            let low_order_bit = remainder & 1;
            accumulator = accumulator ^ (multiplier * low_order_bit);
            multiplier = mul_x(multiplier);
            remainder = remainder >> 1;
        }

        // And we can return the result
        Self {
            byte: accumulator,
        }
    }
}

/// Bytes are displayed as in the AES standard
impl fmt::Display for GFByte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:02x}", self.byte)
    }
}

/// Explicit conversions to and from bytes are provided
impl From<u8> for GFByte {
    fn from(byte: u8) -> Self {
        Self {
            byte: byte,
        }
    }
}
//
impl Into<u8> for GFByte {
    fn into(self) -> u8 {
        self.byte
    }
}

/// In addition, we provide some extra specific crypto primitives on bytes
impl GFByte {
    /// Applying an S-box to a GFByte applies it to the inner byte
    pub fn apply_s_box(&mut self, sb: &SBox) {
        self.byte = sb[self.byte as usize];
    }
}


#[cfg(test)]
mod tests {
    use aes::gf_byte::GFByte;

    // Test that GFByte addition works as expected by the AES spec
    #[test]
    fn add() {
        assert_eq!(GFByte::from(0x57) + GFByte::from(0x83), GFByte::from(0xd4));
    }

    // Test that GFByte multiplication works as expected by the AES spec
    #[test]
    fn mul() {
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x83), GFByte::from(0xc1));
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x02), GFByte::from(0xae));
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x04), GFByte::from(0x47));
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x08), GFByte::from(0x8e));
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x10), GFByte::from(0x07));
        assert_eq!(GFByte::from(0x57) * GFByte::from(0x13), GFByte::from(0xfe));
    }
}
