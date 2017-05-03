//! Internally, the AES algorithm's operations are performed on a
//! two-dimensional array of bytes called the State. It consists of four rows
//! of bytes, each containing Nb bytes (Nb=4 for AES), and directly maps to
//! an input or output block of the cipher.

use aes::{DEC_SBOX, ENC_SBOX, Input, Output, RoundKeys, SBox};
use aes::gf_word::GFWord;
use std::fmt;


// The number of columns in the AES state is denoted Nb
pub const N_B: usize = 4;


/// The internal state of the AES algorithm is made of 128 bits, organized as
/// 4 words of 32 bits, acting as a column-major 4x4 array of bytes.
pub struct State {
    words: [GFWord; N_B],
}

/// The AES state is built from an input block...
impl From<Input> for State {
    fn from(input: Input) -> Self {
        Self {
            words: [GFWord::new(input[0],  input[1],  input[2],  input[3]),
                    GFWord::new(input[4],  input[5],  input[6],  input[7]),
                    GFWord::new(input[8],  input[9],  input[10], input[11]),
                    GFWord::new(input[12], input[13], input[14], input[15])],
        }
    }
}

/// ...and eventually turned back into an output block
impl Into<Output> for State {
    fn into(self) -> Output {
        let (w1, w2) = (self.words[0], self.words[1]);
        let (w3, w4) = (self.words[2], self.words[3]);
        [w1[0].into(), w1[1].into(), w1[2].into(), w1[3].into(),
         w2[0].into(), w2[1].into(), w2[2].into(), w2[3].into(),
         w3[0].into(), w3[1].into(), w3[2].into(), w3[3].into(),
         w4[0].into(), w4[1].into(), w4[2].into(), w4[3].into()]
    }
}

/// The format used for state display differs a bit from that used by the AES
/// spec in order to accomodate the constraint of UNIX terminals better.
impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for word in self.words.iter() {
            write!(f, "{} ", *word)?;
        }
        Ok(())
    }
}

/// The AES encryption and decryption algorithms are specified in terms of
/// operations on the internal state:
impl State {
    /// SubBytes is a non-linear byte substitution that operates independently
    /// on each byte of the state using a substitution table (S-box)
    pub fn sub_bytes(&mut self) {
        self.apply_s_box(&ENC_SBOX);
    }

    /// InvSubBytes is the inverse of the byte substitution transfomrmation, in
    /// which the inverse S-box is applied to each byte of the state
    pub fn inv_sub_bytes(&mut self) {
        self.apply_s_box(&DEC_SBOX);
    }

    /// In the ShiftRows transformation, the bytes in the last three rows of the
    /// state are cyclically shifted by growing amounts of bytes
    pub fn shift_rows(&mut self) {
        for i in 0..4 {
            self.shift_row_left(i, i);
        }
    }

    /// InvShiftRows is the inverse of the ShiftRows transformation. The bytes
    /// in the last three rows of the state are cyclically shifted in the
    /// reverse order with respect to ShiftRows.
    pub fn inv_shift_rows(&mut self) {
        for i in 0..4 {
            self.shift_row_right(i, i);
        }
    }

    /// The MixColumns transformation operates on the state column by column,
    /// treating each column as a four-term polynomial as described above and 
    /// multiplying them by a(x) = 3*x^3 + x^2 + x + 2
    pub fn mix_columns(&mut self) {
        let a = GFWord::new(0x02, 0x01, 0x01, 0x03);
        for word in self.words.iter_mut() {
            *word = *word * a;
        }
    }

    /// InvMixColumns is the inverse of the MixColumns transformation. It
    /// multiplies the columns by inv_a(x) = 0x0b*x^3 + 0x0d*x^2 + 0x09*x + 0x0e
    pub fn inv_mix_columns(&mut self) {
        let inv_a = GFWord::new(0x0e, 0x09, 0x0d, 0x0b);
        for word in self.words.iter_mut() {
            *word = *word * inv_a;
        }
    }

    /// In the AddRoundKey transformation, a Round Key is added to the state by
    /// a simple bitwise XOR operation. AddRoundKey is its own inverse.
    pub fn add_round_key(&mut self, round_keys: &RoundKeys) {
        // A round key should consist of exactly N_B words from the key schedule
        debug_assert_eq!(round_keys.len(), N_B);

        // XOR each column of the state with the key schedule
        for (column, key) in self.words.iter_mut().zip(round_keys.iter()) {
            *column = *column + *key;
        }
    }

    /// This private method applies an S-box to each byte of the state
    fn apply_s_box(&mut self, sb: &SBox) {
        for word in self.words.iter_mut() {
            word.apply_s_box(sb);
        }
    }

    /// This private method shifts a row of bytes to the left
    fn shift_row_left(&mut self, row: usize, amount: usize) {
        let wrapped_amount = amount % N_B;
        match wrapped_amount {
            0 => {},
            1 => { let carry1         = self.words[0][row];
                   self.words[0][row] = self.words[1][row];
                   self.words[1][row] = self.words[2][row];
                   self.words[2][row] = self.words[3][row];
                   self.words[3][row] = carry1; }
            2 => { let carry2        = [self.words[0][row],
                                        self.words[1][row]];
                   self.words[0][row] = self.words[2][row];
                   self.words[1][row] = self.words[3][row];
                   self.words[2][row] = carry2[0];
                   self.words[3][row] = carry2[1]; }
            3 => { self.shift_row_right(row, 1); }
            _ => { panic!("This cannot happen with N_B == 4"); }
        }
    }

    /// This private method shifts a row of bytes to the right
    fn shift_row_right(&mut self, row: usize, amount: usize) {
        let wrapped_amount = amount % N_B;
        match wrapped_amount {
            0 => {},
            1 => { let carry1         = self.words[3][row];
                   self.words[3][row] = self.words[2][row];
                   self.words[2][row] = self.words[1][row];
                   self.words[1][row] = self.words[0][row];
                   self.words[0][row] = carry1; }
            2 => { self.shift_row_left(row, 2); }
            3 => { self.shift_row_left(row, 1); }
            _ => { panic!("This cannot happen with N_B == 4"); }
        }
    }
}
