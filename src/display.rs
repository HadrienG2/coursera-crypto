//! Facilities for displaying ASCII-derived cryptographic messages


// If the requested byte maps to a printable ASCII character, returns it.
// Otherwise, return an unambiguously non-ASCII printable character.
pub fn as_printable_char(byte: u8) -> char {
    match byte {
        // Can be interpreted as a printable ASCII character
        b if b >= 0x20 && b <= 0x7E => b as char,
        // Cannot be interpreted as printable ASCII
        _ => '࿕',
    }
}


// Display a set of messages column-wise, both in numerical form and after
// conversion to a character using the provided method
pub fn print_columns<P>(labels: &[String], messages: &[Vec<u8>], to_char: P)
    where P: Fn(u8) -> char
{
    // We should have as many labels as we have columns of bytes
    assert_eq!(labels.len(), messages.len());

    // Determine how many lines of output we will print. Being requested to
    // print zero messages is probably an error, so we'll panic in this case.
    let output_len = ::max_length(&messages).unwrap();

    // Display the labels
    println!();
    for label in labels.iter() {
        print!("{}\t", *label);
    }
    println!();
    println!();

    // Print the messages in a columnar layout
    for line in 0..output_len {
        for message in messages.iter() {
            if line < message.len() {
                let byte = message[line];
                print!("{} {}", to_char(byte), byte);
            } else {
                print!("   ");
            }
            print!("\t");
        }
        println!();
    }
    println!();
}
