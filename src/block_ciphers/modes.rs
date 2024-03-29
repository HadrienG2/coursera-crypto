//! This module implementes various block cipher modes of operation

use blocks::{self, Block128u8, BLOCK_LEN_128_U8};
use padding::PaddingScheme;
use inplace_xor_bytes;


// This is an implementation of the Cipher Block Chaining mode of operation for
// block ciphers. At the moment, it is specific to 128-bit blocks of bytes.
//
// Its inputs should be built as follows:
//
// * Construct a closure which combines your block cipher of choice with its
//   key schedule, removing any cipher-specific dependence on a given key type
// * Provide an appropriate IV (and remember to transmit it to your recipient)
// * Pad the input message into a stream of complete blocks using your
//   padding scheme of choice (e.g. the PKCS#7 one)
//
pub fn cbc_128u8<'a, KC, PI>(keyed_cipher: &KC,
                             init_vector: Block128u8,
                             padded_input: PI) -> Vec<u8>
    where KC: Fn(&Block128u8) -> Block128u8,
          PI: PaddingScheme<'a, Block128u8>
{
    // Map the stream of input blocks into a stream of CBC-encrypted blocks
    let mut last_ciphertext = init_vector;
    let output_iter = padded_input.map(move |mut block| {
        inplace_xor_bytes(&mut block[..], &last_ciphertext[..]);
        last_ciphertext = keyed_cipher(&block);
        last_ciphertext
    });

    // Collect the output blocks into an output ciphertext
    blocks::into_vec_128u8(output_iter)
}


// This is the decryption primitive associated with the CBC cipher mode.
// It works much like encryption except for the facts that it uses the inverse
// cipher and that the input is a message instead of a block iterator.
//
// The input must be valid CBC-encoded ciphertext, so its size should be a
// multiple of the block size. Otherwise, decryption will return None.
//
pub fn inv_cbc_128u8<KIC>(keyed_inv_cipher: &KIC,
                          init_vector: Block128u8,
                          input: &[u8]) -> Option<Vec<u8>>
    where KIC: Fn(&Block128u8) -> Block128u8
{
    // Make sure that the input is a reasonable sequence of blocks, and produce
    // an iterator of blocks out of it
    let input_len = input.len();
    if input_len % BLOCK_LEN_128_U8 != 0 { return None; }
    let input_iter = input.chunks(BLOCK_LEN_128_U8)
                          .map(|slice| blocks::as_block_128u8(slice));

    // Map the stream of input blocks into a stream of CBC-decrypted blocks
    let mut last_ciphertext = &init_vector;
    let output_iter = input_iter.map(move |ciphertext_block| {
        let mut result = keyed_inv_cipher(ciphertext_block);
        inplace_xor_bytes(&mut result[..], &last_ciphertext[..]);
        last_ciphertext = ciphertext_block;
        result
    });

    // Collect the output blocks into an output message
    let mut output_vec = blocks::into_vec_128u8(output_iter);

    // Discard the padding and output the final message
    let padding_bytes = output_vec[input_len-1];
    output_vec.truncate(input_len - padding_bytes as usize);
    Some(output_vec)
}


// This is the encryption/decryption primitive associated with the CTR cipher
// mode, which is its own inverse and requires no input padding.
pub fn ctr_128u8<KC>(keyed_cipher: &KC,
                     init_vector: Block128u8,
                     input: &[u8]) -> Vec<u8>
    where KC: Fn(&Block128u8) -> Block128u8
{
    // CTR is based on maintaining an internal counter, starting at the IV
    let mut counter = init_vector;
    let mut next_counter = move || -> Block128u8 {
        let old_counter = counter;
        let mut index = BLOCK_LEN_128_U8 - 1;
        loop {
            let (new_value, overflow) = counter[index].overflowing_add(1);
            counter[index] = new_value;
            if !overflow { break; }
            index = if index != 0 { index-1 } else { BLOCK_LEN_128_U8-1 };
        }
        old_counter
    };

    // We build our output by XORing the input bytes with the encrypted counter,
    // which acts as a one-time pad, operating as a stream cipher
    let mut output = Vec::with_capacity(input.len());
    for input in input.chunks(BLOCK_LEN_128_U8) {
        let counter = next_counter();
        let one_time_pad = keyed_cipher(&counter);
        for (input_byte, otp_byte) in input.iter().zip(one_time_pad.iter()) {
            output.push(input_byte ^ otp_byte);
        }
    }
    output
}
