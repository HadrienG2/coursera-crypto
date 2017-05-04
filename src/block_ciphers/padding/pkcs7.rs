//! This module implements the PKCS#7 padding scheme for turning an arbitrary
//! slice of bytes into a stream of fixed-size blocks that can be used as input
//! to a block cipher.

use block_ciphers::{Block128, BLOCK_SIZE_128};
use block_ciphers::padding::Padding128;
use std::slice::Chunks;


// For now, only a version for 128-bit blocks is implemented
pub struct PKCS7Padding128<'a> {
    raw_iterator: Chunks<'a, u8>,
    final_block_sent: bool,
    block_count: usize,
}

// A padding schemes behaves as an iterator of blocks
impl<'a> Iterator for PKCS7Padding128<'a> {
    type Item = Block128;

    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iterator.next() {
            // Input slices are forwarded to the output, possibly with padding
            Some(ref slice) => {
                // Copy all bytes from the input slice to the output block
                let mut result = [0; BLOCK_SIZE_128];
                for (input, output) in slice.iter().zip(result.iter_mut()) {
                    *output = *input
                }

                // Add PKCS#7 compliant padding at the end if needed
                let remaining = (BLOCK_SIZE_128 - slice.len()) as u8;
                if remaining > 0 {
                    for output in result[slice.len()..].iter_mut() {
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
                    Some([BLOCK_SIZE_128 as u8; BLOCK_SIZE_128])
                }
            }
        }
    }
}

// It also implements every other extra required of a padding scheme
impl<'a> Padding128<'a> for PKCS7Padding128<'a> {
    // It is constructed from a message (slice of bytes)
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            raw_iterator: bytes.chunks(BLOCK_SIZE_128),
            final_block_sent: false,
            block_count: bytes.len()/BLOCK_SIZE_128 + 1,
        }
    }

    // It knows its output size precisely
    fn len(&self) -> usize {
        self.block_count
    }
}


#[cfg(test)]
mod tests {
    use block_ciphers::padding::Padding128;
    use block_ciphers::padding::pkcs7::PKCS7Padding128;

    #[test]
    fn empty_input() {
        let input = &[];
        let mut padded_iter = PKCS7Padding128::new(input);
        assert_eq!(padded_iter.next(), Some([16, 16, 16, 16, 16, 16, 16, 16,
                                             16, 16, 16, 16, 16, 16, 16, 16]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn one_byte_input() {
        let input = &[42];
        let mut padded_iter = PKCS7Padding128::new(input);
        assert_eq!(padded_iter.next(), Some([42, 15, 15, 15, 15, 15, 15, 15,
                                             15, 15, 15, 15, 15, 15, 15, 15]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn fifteen_byte_input() {
        let input = &[42, 42, 42, 42, 42, 42, 42, 42,
                      42, 42, 42, 42, 42, 42, 42];
        let mut padded_iter = PKCS7Padding128::new(input);
        assert_eq!(padded_iter.next(), Some([42, 42, 42, 42, 42, 42, 42, 42,
                                             42, 42, 42, 42, 42, 42, 42, 1]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn sixteen_byte_input() {
        let input = &[42, 42, 42, 42, 42, 42, 42, 42,
                      42, 42, 42, 42, 42, 42, 42, 42];
        let mut padded_iter = PKCS7Padding128::new(input);
        assert_eq!(padded_iter.next(), Some([42, 42, 42, 42, 42, 42, 42, 42,
                                             42, 42, 42, 42, 42, 42, 42, 42]));
        assert_eq!(padded_iter.next(), Some([16, 16, 16, 16, 16, 16, 16, 16,
                                             16, 16, 16, 16, 16, 16, 16, 16]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn seventeen_byte_input() {
        let input = &[42, 42, 42, 42, 42, 42, 42, 42,
                      42, 42, 42, 42, 42, 42, 42, 42,
                      42];
        let mut padded_iter = PKCS7Padding128::new(input);
        assert_eq!(padded_iter.next(), Some([42, 42, 42, 42, 42, 42, 42, 42,
                                             42, 42, 42, 42, 42, 42, 42, 42]));
        assert_eq!(padded_iter.next(), Some([42, 15, 15, 15, 15, 15, 15, 15,
                                             15, 15, 15, 15, 15, 15, 15, 15]));
        assert_eq!(padded_iter.next(), None);
    }
}
