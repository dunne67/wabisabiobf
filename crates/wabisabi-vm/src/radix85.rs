/// Standard WABI ASCII85 armor (`'!'..='u'`, ASCII `33..=117`) with `'z'` zero-word
/// (`"!!!!!"` == `0x00000000`) compression and `"WABI"` 4-byte protocol header.
pub struct Radix85;

impl Radix85 {
    /// Pads `data` with zero bytes to a 4-byte boundary, prepends `"WABI"`, encodes each
    /// little-endian `u32` word into 5 big-endian base-85 digits (`chr(digit + 33)`),
    /// compresses `"!!!!!"` (`0x00000000`) to `'z'`, and returns `(escaped_lua_literal_inner, padded_len)`.
    pub fn encode_escaped(data: &[u8]) -> (String, usize) {
        let rem = data.len() % 4;
        let pad = if rem == 0 { 0 } else { 4 - rem };
        let padded_len = data.len() + pad;

        let mut buf = Vec::with_capacity(padded_len);
        buf.extend_from_slice(data);
        buf.resize(padded_len, 0u8);

        let mut raw = String::with_capacity(4 + (padded_len / 4) * 5);
        raw.push_str("WABI");
        for chunk in buf.chunks_exact(4) {
            let mut w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            if w == 0 {
                raw.push('z');
            } else {
                let mut digits = [0u8; 5];
                for slot in (0..5).rev() {
                    digits[slot] = ((w % 85) as u8) + 33;
                    w /= 85;
                }
                for &b in &digits {
                    raw.push(b as char);
                }
            }
        }

        let mut escaped = String::with_capacity(raw.len() + 64);
        for ch in raw.chars() {
            match ch {
                '\\' => escaped.push_str("\\\\"),
                '"' => escaped.push_str("\\\""),
                _ => escaped.push(ch),
            }
        }

        (escaped, padded_len)
    }
}
