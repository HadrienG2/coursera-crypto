// This module implements the padding scheme typically used by hashing
// algorithms based on the Merkle-Damgård construction:
//
// * Append the bit "1" at the end of the message
// * Append the bit "0" until we're 64 bits before the end of the message
// * Complete padding with the message length, in bits, as a 64-bit word

use blocks::{Block512u32, BLOCK_LEN_512_U32};
use padding::PaddingScheme;
use std::mem;
use std::slice::Chunks;


// Due to current Rust limitations on genericity over array types, only 512-bit
// blocks of 32-bit words are currently supported as a padding unit
pub struct MDPadding512u32<'a> {
    // Raw chunks of bytes from the input message
    raw_iterator: Chunks<'a, u8>,

    // Status of the iteration process
    final_bit_sent: bool,
    message_len_sent: bool,

    // Original message size in bytes
    message_len: usize,
}

// A padding schemes behaves as an iterator of blocks
impl<'a> Iterator for MDPadding512u32<'a> {
    type Item = Block512u32;

    // It produces padded blocks
    fn next(&mut self) -> Option<Self::Item> {
        match self.raw_iterator.next() {
            // Input bytes are forwarded to the output as words, with padding
            Some(ref input_slice) => {
                // Check input slice size and prepare output block
                let input_len = input_slice.len();
                let mut result = [0u32; BLOCK_LEN_512_U32];

                // Turn bytes from the input slice into words of output block
                for (inputs, output) in input_slice.chunks(4)
                                                   .zip(result.iter_mut()) {
                    for (index, byte) in inputs.iter().enumerate() {
                        *output |= (*byte as u32) << ((3-index) * 8);
                    }
                }

                // Add padding at the end if there is room left
                let block_size_u8 = mem::size_of::<Block512u32>();
                if input_len < block_size_u8 {
                    // Start with a '1' bit, which comes after the last byte
                    let word_index = input_len / 4;
                    let word_shift = (3 - (input_len % 4)) * 8;
                    result[word_index] |= 1 << 7+word_shift;
                    self.final_bit_sent = true;

                    // Add message length in bits if there is enough room
                    if block_size_u8 - (input_len+1) >= 8 {
                        self.fill_length(&mut result);
                        self.message_len_sent = true;
                    }
                }

                // Return the (possibly padded) block
                Some(result)
            }

            // Add any padding that we haven't sent yet after the end of input
            None => {
                if self.message_len_sent {
                    // All padding has been sent, we're done
                    None
                } else {
                    // Setup our last output block
                    let mut result = [0u32; BLOCK_LEN_512_U32];

                    // Send the '1' bit if we haven't done so yet
                    if !self.final_bit_sent {
                        result[0] = 1 << 31;
                        self.final_bit_sent = true;
                    }

                    // Append the message length in bits at the end
                    self.fill_length(&mut result);
                    self.message_len_sent = true;

                    // Send the final block
                    Some(result)
                }
            }
        }
    }

    // It knows its size precisely
    fn size_hint(&self) -> (usize, Option<usize>) {
        // Count how many fully filled blocks we have in our message
        let block_size_u8 = mem::size_of::<Block512u32>();
        let full_blocks = self.message_len / block_size_u8;

        // Count how many extra message blocks must be allocated, taking into
        // account that in addition to the remaining message bytes we must also
        // send one "1" bit (=0x80 byte) + the message length as a 64-bit number
        let remaining_message_bytes = self.message_len % block_size_u8;
        let remaining_bytes = remaining_message_bytes + 1 + 64/8;
        let extra_blocks = if remaining_bytes <= block_size_u8 { 1 } else { 2 };
        let block_count = full_blocks + extra_blocks;

        // Tell that to the client
        (block_count, Some(block_count))
    }
}

// It also implements every other extra required of a padding scheme
impl<'a> PaddingScheme<'a, Block512u32> for MDPadding512u32<'a> {
    // It is constructed from a message (slice of bytes)
    fn new(bytes: &'a [u8]) -> Self {
        let block_size_u8 = mem::size_of::<Block512u32>();
        Self {
            raw_iterator: bytes.chunks(block_size_u8),
            final_bit_sent: false,
            message_len_sent: false,
            message_len: bytes.len(),
        }
    }
}

// Implementation details go here
impl<'a> MDPadding512u32<'a> {
    // Private method to fill the message length in bits at the end of a block
    fn fill_length(&self, block: &mut Block512u32) {
        let message_bits = (self.message_len as u64) * 8;
        let high_order_word = (message_bits >> 32) as u32;
        let low_order_word = (message_bits & 0xffffffff) as u32;
        block[BLOCK_LEN_512_U32 - 2] = high_order_word;
        block[BLOCK_LEN_512_U32 - 1] = low_order_word;
    }
}


#[cfg(test)]
mod tests {
    use blocks::Block512u32;
    use padding::PaddingScheme;
    use padding::merkle_damgard::MDPadding512u32;
    use std::mem;

    #[test]
    fn empty_input() {
        let input = [];
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0x80000000, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn one_byte_input() {
        let input = [0x42];
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0x42_800000, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 8]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn block_minus_9_bytes_input() {
        let input = [0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
                     0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52,
                     0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a,
                     0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
                     0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
                     0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
                     0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79];
        assert_eq!(input.len(), mem::size_of::<Block512u32>() - 9);
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0x43444546, 0x4748494a,
                                             0x4b4c4d4e, 0x4f505152,
                                             0x53545556, 0x5758595a,
                                             0x5b5c5d5e, 0x5f606162,
                                             0x63646566, 0x6768696a,
                                             0x6b6c6d6e, 0x6f707172,
                                             0x73747576, 0x777879_80,
                                             0, 512-9*8]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn block_minus_8_bytes_input() {
        let input = [0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
                     0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
                     0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91,
                     0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
                     0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1,
                     0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
                     0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1];
        assert_eq!(input.len(), mem::size_of::<Block512u32>() - 8);
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0x7a7b7c7d, 0x7e7f8081,
                                             0x82838485, 0x86878889,
                                             0x8a8b8c8d, 0x8e8f9091,
                                             0x92939495, 0x96979899,
                                             0x9a9b9c9d, 0x9e9fa0a1,
                                             0xa2a3a4a5, 0xa6a7a8a9,
                                             0xaaabacad, 0xaeafb0b1,
                                             0x80000000, 0]));
        assert_eq!(padded_iter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 512-8*8]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn block_minus_one_byte_input() {
        let input = [0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9,
                     0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1,
                     0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9,
                     0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1,
                     0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9,
                     0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1,
                     0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
                     0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0];
        assert_eq!(input.len(), mem::size_of::<Block512u32>() - 1);
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0xb2b3b4b5, 0xb6b7b8b9,
                                             0xbabbbcbd, 0xbebfc0c1,
                                             0xc2c3c4c5, 0xc6c7c8c9,
                                             0xcacbcccd, 0xcecfd0d1,
                                             0xd2d3d4d5, 0xd6d7d8d9,
                                             0xdadbdcdd, 0xdedfe0e1,
                                             0xe2e3e4e5, 0xe6e7e8e9,
                                             0xeaebeced, 0xeeeff0_80]));
        assert_eq!(padded_iter.next(), Some([0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 512-8]));
        assert_eq!(padded_iter.next(), None);
    }

    #[test]
    fn full_block_input() {
        let input = [0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8,
                     0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00,
                     0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                     0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                     0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                     0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
                     0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                     0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30];
        assert_eq!(input.len(), mem::size_of::<Block512u32>());
        let mut padded_iter = MDPadding512u32::new(&input);
        assert_eq!(padded_iter.next(), Some([0xf1f2f3f4, 0xf5f6f7f8,
                                             0xf9fafbfc, 0xfdfeff00,
                                             0x01020304, 0x05060708,
                                             0x090a0b0c, 0x0d0e0f10,
                                             0x11121314, 0x15161718,
                                             0x191a1b1c, 0x1d1e1f20,
                                             0x21222324, 0x25262728,
                                             0x292a2b2c, 0x2d2e2f30]));
        assert_eq!(padded_iter.next(), Some([0x80000000, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0, 512]));
        assert_eq!(padded_iter.next(), None);
    }
}
