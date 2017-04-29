//! Facilities for manipulating hexadecimal data stored in files
//!
//! As part of the week 1 assignment of Coursera's Cryptography 1 course, one
//! must manipulate hex-encoded ciphertext. This module is dedicated to loading
//! such ciphertext from a file, into a more convenient array of bytes.

use std::fs::File;
use std::io::{self, Read};
use std::result::Result;


/// Possible errors when trying to load the hexadecimal data
#[derive(Debug)]
pub enum Error {
    /// The string could not be loaded from the file
    Loading(io::Error),

    /// The file contains an odd number of characters, and thus cannot be
    /// interpreted as the hexadecimal representation of a stream of bytes
    OddLength,

    /// The file contains characters which are not valid hexadecimal digits
    InvalidChars
}


/// Load hex-encoded bytes from a file
pub fn load_bytes(filename: &str) -> Result<Vec<u8>, Error> {
    // Fetch an hex string from a file, and strip any trailing newline
    let mut raw_str = String::new();
    {
        let mut input_file = File::open(filename).map_err(Error::Loading)?;
        input_file.read_to_string(&mut raw_str).map_err(Error::Loading)?;
    }
    let trimmed_str = raw_str.trim_right();

    // Check that the string has the right length
    if trimmed_str.len() % 2 != 0 { return Err(Error::OddLength); }

    // Decode it into a vector of bytes
    let mut chars = trimmed_str.chars();
    let mut bytes = Vec::new();
    while let (Some(ch1), Some(ch2)) = (chars.next(), chars.next()) {
        let digit1 = ch1.to_digit(16).ok_or(Error::InvalidChars)?;
        let digit2 = ch2.to_digit(16).ok_or(Error::InvalidChars)?;
        bytes.push((digit1 * 16 + digit2) as u8);
    }

    // Return the bytes
    Ok(bytes)
}
