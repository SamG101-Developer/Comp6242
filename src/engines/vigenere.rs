use crate::engines::utils;
use std::collections::HashMap;


/// Crack a ciphertext encrypted with a Vigenere cipher. This is the wrapper function that calls all
/// the helper functions and determines the key.
pub fn crack(ciphertext: String) -> String {
    let english_frequencies = vec![
        0.082, // 'a'
        0.015, // 'b'
        0.028, // 'c'
        0.043, // 'd'
        0.127, // 'e'
        0.022, // 'f'
        0.020, // 'g'
        0.061, // 'h'
        0.070, // 'i'
        0.002, // 'j'
        0.008, // 'k'
        0.040, // 'l'
        0.024, // 'm'
        0.067, // 'n'
        0.075, // 'o'
        0.019, // 'p'
        0.001, // 'q'
        0.060, // 'r'
        0.063, // 's'
        0.091, // 't'
        0.028, // 'u'
        0.010, // 'v'
        0.024, // 'w'
        0.002, // 'x'
        0.019, // 'y'
        0.001, // 'z'
    ];

    // Call each helper function in turn to deduce more information about the key.
    let sanitized_ciphertext = utils::sanitize_input(&ciphertext);
    let repeated_sequences = find_repeated_sequences(&sanitized_ciphertext);
    let sequence_differences = find_differences(repeated_sequences);
    let gcd = utils::gcd(sequence_differences.into_iter().map(|(_, x)| x).flatten().collect());
    let blocks = group_ciphertext_into_blocks(&sanitized_ciphertext, gcd);

    // Crack each Ceaser-cipher encrypted block using frequency analysis to determine the subkey.
    let mut key = String::new();
    for block in blocks {
        let mut block_key = 'a';
        let mut best_frequency = 10.0;

        // Test each shift of the alphabet to determine the best subkey for this block.
        for i in 0..26 {

            // Decrypt a block using the current shift.
            let mut decryption_candidate = String::new();
            for mut c in block.bytes() {
                c -= 97;
                let decrypted_char = ((c + 26 - i) % 26) + 97;

                // let c = alphabet.iter().position(|&x| x == c).unwrap();
                // let decrypted_char = alphabet[(c + 26 - i) % 26];
                decryption_candidate.push(decrypted_char as char);
            }

            // Determine how close to English the decrypted block is, by frequency analysis.
            let mut frequency_map = frequency_analysis(&decryption_candidate);
            let mut score = 0.0;
            for index in 0..26 {
                score += (frequency_map.remove(0) - english_frequencies[index]).abs();
            }

            // If this is the best score so far, update the best score and the subkey.
            if score < best_frequency {
                best_frequency = score;
                block_key = (i + 97) as char;
            }
        }

        // Add the subkey to the key.
        key.push(block_key);
    }

    // Decrypt the ciphertext using the key.
    vigenere_decrypt(&ciphertext, &key)
}


/// Find repeated sequences of length 3-6 (performance considerations) throughout the ciphertext.
/// The output map contains each sequence, and the indices at which they appear.
fn find_repeated_sequences(ciphertext: &String) -> Vec<(String, Vec<usize>)> {
    let mut output_map = Vec::new();

    // Test n-grams of length 3 to 6 inclusive.
    for word_len in 3..=6 {
        let mut seen = HashMap::with_capacity(128);

        // Add each sequence of length "word_len" to the map.
        for index in 0..=(ciphertext.len() - word_len) {
            let sequence = &ciphertext[index..(index + word_len)];
            seen.entry(sequence).or_insert_with(Vec::new).push(index);
        }

        // Keep only the sequences that appear more than twice.
        for (sequence, indices) in seen {
            if indices.len() > 2 {
                output_map.push((sequence.to_string(), indices));
            }
        }
    }
    output_map
}

/// Given a list of repeated sequences, find the differences between each index. This takes a record
/// like {"aa": [1, 4, 10]} and turns it into {"aa": [3, 6]}.
fn find_differences(repeated_sequences: Vec<(String, Vec<usize>)>) -> Vec<(String, Vec<usize>)> {
    let mut output_map = Vec::new();

    // Calculate the differences between each index for each sequence.
    for (sequence, indices) in repeated_sequences {
        let mut differences = Vec::new();
        for i in 0..(indices.len() - 1) {
            differences.push(indices[i + 1] - indices[i]);
        }
        output_map.push((sequence, differences));
    }
    output_map
}

/// Given a ciphertext and a key length, group the ciphertext into "key_length" number of blocks.
/// The blocks aren't made by chopping the ciphertext into n consecutive blocks, but by putting each
/// consecutive character into the next block.
fn group_ciphertext_into_blocks(ciper_text: &String, key_length: usize) -> Vec<String> {
    let mut blocks = vec![String::new(); key_length];

    // Place each character into the next bock, using a modulus to cycle through the blocks.
    for (i, c) in ciper_text.chars().enumerate() {
        blocks[i % key_length].push(c);
    }
    blocks
}


/// Perform frequency analysis on a block of text. The output is a map of character -> frequency.
/// Calculated by determining the number of times each character appears in the block, and dividing
/// by the total number of characters.
fn frequency_analysis(block: &String) -> Vec<f64> {
    // Default map, all characters have a frequency of 0.
    let mut frequency_map = Vec::with_capacity(26);
    for _ in 0..26 {
        frequency_map.push(0.0);
    }

    // Increment the count for each character in the block.
    for character in block.chars() {
        frequency_map[character as usize - 97] += 1.0;
    }

    // Divide each count by the total number of characters to get the frequency.
    let block_length = block.len() as f64;
    for count in frequency_map.iter_mut() {
        *count /= block_length;
    }
    frequency_map
}


/// Decrypt a ciphertext using the provided key. The key is repeated as necessary to match the
/// length of the ciphertext. The non-sanitised ciphertext is provided into this function, so keep
/// punctuation and spaces in the output.
fn vigenere_decrypt(ciphertext: &String, key: &String) -> String {
    let mut decrypted = String::new();
    let mut key = key.bytes().cycle();

    // Iterate through each character in the ciphertext. Use .chrs() for non-ascii characters.
    for mut c in ciphertext.chars() {
        c = c.to_ascii_lowercase();

        // Skip characters that aren't in the alphabet.
        if 97 > c as u8 || c as u16 > 122 {
            decrypted.push(c);
            continue;
        }

        // Decrypt the character using the key.
        let k = key.next().unwrap() - 97;
        let c = c as u8 - 97;
        let decrypted_char = ((c + 26 - k) % 26) + 97;
        decrypted.push(decrypted_char as char);
    }
    decrypted
}
