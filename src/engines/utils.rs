/// Calculate the greatest common divisor of a list of numbers. Works by iterating through the list
/// and testing the current gcd with the next number.
pub fn gcd(values: Vec<u64>) -> u64 {
    let mut gcd = values[0];
    for value in values {
        gcd = gcd_inner(gcd, value);
    }
    gcd
}

/// Calculate the greatest common divisor of two numbers using Euclid's algorithm.
fn gcd_inner(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        gcd_inner(b, a % b)
    }
}


/// Sanitize the input by removing spaces, commas, fullstops, and apostrophes, and converting to
/// lowercase.
pub fn sanitize_input(input: &String) -> String {
    input
        .replace(" ", "")
        .replace(",", "")
        .replace(".", "")
        .replace("‘", "")
        .replace("’", "")
        .to_lowercase()
}
