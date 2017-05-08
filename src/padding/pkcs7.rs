//! This module implements the PKCS#7 padding scheme for turning an arbitrary
//! slice of bytes into a stream of fixed-size blocks.

use blocks::{Block128u8, BLOCK_LEN_128_U8};
use padding::PaddingScheme;
use std::mem;
use std::slice::Chunks;


// Due to current Rust limitations on genericity over array types, only 128-bit
// blocks of bytes are currently supported as a padding unit
pub struct PKCS7Padding128u8<'a> {
    raw_iterator: Chunks<'a, u8>,
    final_block_sent: bool,
    block_count: usize,
}

// A padding schemes behaves as an iterator of blocks
impl<'a> Iterator for PKCS7Padding128u8<'a> {
    type Item = Block128u8;

    // It produces padded blocks
    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iterator.next() {
            // Input slices are forwarded to the output, possibly with padding
            Some(ref input_slice) => {
                // Copy all bytes from the input slice to the output block
                let input_len = input_slice.len();
                let mut result = [0; BLOCK_LEN_128_U8];
                result[..input_len].copy_from_slice(input_slice);

                // Add PKCS#7 compliant padding at the end if needed
                let remaining = (BLOCK_LEN_128_U8 - input_len) as u8;
                if remaining > 0 {
                    for output in result[input_len..].iter_mut() {
                        *output = remaining;
                    }
                    self.final_block_sent = true;
                }

                // Return the (possibly padded) block
                Some(result)
            }

            // If all inputs had exactly the right size, add a padding block
            // at the end, filled with 16 (the size of the padding block).
            None => {
                if self.final_block_sent {
                    None
                } else {
                    self.final_block_sent = true;
                    Some([BLOCK_LEN_128_U8 as u8; BLOCK_LEN_128_U8])
                }
            }
        }
    }

    // It knows its size precisely
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.block_count, Some(self.block_count))
    }
}

// It also implements every other extra required of a padding scheme
impl<'a> PaddingScheme<'a, Block128u8> for PKCS7Padding128u8<'a> {
    // It is constructed from a message (slice of bytes)
    fn new(bytes: &'a [u8]) -> Self {
        let block_size_u8 = mem::size_of::<Block128u8>();
        Self {
            raw_iterator: bytes.chunks(block_size_u8),
            final_block_sent: false,
            block_count: bytes.len()/block_size_u8 + 1,
        }
    }
}


#[cfg(test)]
mod tests {
    use padding::PaddingScheme;
    use padding::pkcs7::PKCS7Padding128u8;

    #[test]
    fn empty_input() {
        let input = &[];
        let mut padded_iter = PKCS7Padding128u8::new(input);
        assert_eq!(padded_iter.next(), Some([16, 16, 16, 16, 16, 16, 16, 16,
                                             16, 16, 16, 16, 16, 16, 16, 16]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn one_byte_input() {
        let input = &[42];
        let mut padded_iter = PKCS7Padding128u8::new(input);
        assert_eq!(padded_iter.next(), Some([42, 15, 15, 15, 15, 15, 15, 15,
                                             15, 15, 15, 15, 15, 15, 15, 15]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn fifteen_byte_input() {
        let input = &[43, 44, 45, 46, 47, 48, 49, 50,
                      51, 52, 53, 54, 55, 56, 57];
        let mut padded_iter = PKCS7Padding128u8::new(input);
        assert_eq!(padded_iter.next(), Some([43, 44, 45, 46, 47, 48, 49, 50,
                                             51, 52, 53, 54, 55, 56, 57, 1]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn sixteen_byte_input() {
        let input = &[58, 59, 60, 61, 62, 63, 64, 65,
                      66, 67, 68, 69, 70, 71, 72, 73];
        let mut padded_iter = PKCS7Padding128u8::new(input);
        assert_eq!(padded_iter.next(), Some([58, 59, 60, 61, 62, 63, 64, 65,
                                             66, 67, 68, 69, 70, 71, 72, 73]));
        assert_eq!(padded_iter.next(), Some([16, 16, 16, 16, 16, 16, 16, 16,
                                             16, 16, 16, 16, 16, 16, 16, 16]));
        assert_eq!(padded_iter.next(), None);
    }
}
