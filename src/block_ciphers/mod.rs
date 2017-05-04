//! This module provides tools related to block ciphers: implementation of some
//! ciphers, various operating modes, padding...

pub mod aes;
pub mod padding;

// This is a 128-bit block, which is for now the only block size that we support
pub const BLOCK_SIZE_128: usize = 128/8;
pub type Block128 = [u8; BLOCK_SIZE_128];
