use crate::token::{Span, Token, TokenKind};
use std::fmt;

#[derive(Debug, Clone)]
pub struct SyntaxError {
    pub message: String,
    pub span: Span,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SyntaxError at {}:{}: {}",
            self.span.line, self.span.col, self.message
        )
    }
}

impl std::error::Error for SyntaxError {}

pub struct Lexer<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
    /// Stack of open `{` brace counts inside interpolated string expressions.
    interp_brace_stack: Vec<usize>,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        let bytes = src.as_bytes();
        let mut pos = 0;
        let mut line = 1;
        let mut col = 1;

        // Skip UTF-8 BOM if present
        if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
            pos = 3;
        }
        // Skip optional leading shebang line (#!...) for Luau CLI scripts
        if bytes[pos..].starts_with(b"#!") {
            while pos < bytes.len() && bytes[pos] != b'\n' {
                pos += 1;
            }
            if pos < bytes.len() && bytes[pos] == b'\n' {
                pos += 1;
                line += 1;
                col = 1;
            }
        }

        Self {
            bytes,
            pos,
            line,
            col,
            interp_brace_stack: Vec::new(),
        }
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>, SyntaxError> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = tok.kind == TokenKind::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }

    fn span(&self) -> Span {
        Span {
            line: self.line,
            col: self.col,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.bytes.get(self.pos).copied()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn skip_whitespace_and_comments(&mut self) -> Result<(), SyntaxError> {
        loop {
            while let Some(b) = self.peek() {
                if b.is_ascii_whitespace() {
                    self.bump();
                } else {
                    break;
                }
            }

            if self.peek() == Some(b'-') && self.peek_at(1) == Some(b'-') {
                self.bump();
                self.bump();
                if self.peek() == Some(b'[') {
                    if let Some(eq_count) = self.check_long_bracket_open() {
                        let start = self.span();
                        let _ = self.read_long_string(eq_count, start, true)?;
                        continue;
                    }
                }
                while let Some(b) = self.peek() {
                    if b == b'\n' {
                        break;
                    }
                    self.bump();
                }
                continue;
            }

            break;
        }
        Ok(())
    }

    fn check_long_bracket_open(&self) -> Option<usize> {
        if self.peek() != Some(b'[') {
            return None;
        }
        let mut idx = 1;
        while self.peek_at(idx) == Some(b'=') {
            idx += 1;
        }
        if self.peek_at(idx) == Some(b'[') {
            Some(idx - 1)
        } else {
            None
        }
    }

    fn read_long_string(
        &mut self,
        eq_count: usize,
        start: Span,
        is_comment: bool,
    ) -> Result<Vec<u8>, SyntaxError> {
        // Consume '[' '='* '['
        self.bump();
        for _ in 0..eq_count {
            self.bump();
        }
        self.bump();

        // Strip immediate newline (\r\n or \n) after opening long bracket
        if self.peek() == Some(b'\r') && self.peek_at(1) == Some(b'\n') {
            self.bump();
            self.bump();
        } else if self.peek() == Some(b'\n') {
            self.bump();
        }

        let mut out = Vec::new();
        loop {
            match self.peek() {
                None => {
                    return Err(SyntaxError {
                        message: if is_comment {
                            "unterminated long comment".into()
                        } else {
                            "unterminated long string".into()
                        },
                        span: start,
                    });
                }
                Some(b']') => {
                    let mut matched = true;
                    for i in 0..eq_count {
                        if self.peek_at(1 + i) != Some(b'=') {
                            matched = false;
                            break;
                        }
                    }
                    if matched && self.peek_at(1 + eq_count) == Some(b']') {
                        self.bump();
                        for _ in 0..eq_count {
                            self.bump();
                        }
                        self.bump();
                        return Ok(out);
                    }
                    let b = self.bump().unwrap();
                    if !is_comment {
                        out.push(b);
                    }
                }
                Some(b'\r') => {
                    self.bump();
                    if self.peek() == Some(b'\n') {
                        self.bump();
                    }
                    if !is_comment {
                        out.push(b'\n');
                    }
                }
                Some(_) => {
                    let b = self.bump().unwrap();
                    if !is_comment {
                        out.push(b);
                    }
                }
            }
        }
    }

    fn read_escape(&mut self, out: &mut Vec<u8>, allow_interp_braces: bool) -> Result<(), SyntaxError> {
        let esc_span = self.span();
        let Some(esc) = self.bump() else {
            return Err(SyntaxError {
                message: "unterminated escape sequence".into(),
                span: esc_span,
            });
        };
        match esc {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0C),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0B),
            b'\\' => out.push(b'\\'),
            b'\'' => out.push(b'\''),
            b'"' => out.push(b'"'),
            b'`' if allow_interp_braces => out.push(b'`'),
            b'{' if allow_interp_braces => out.push(b'{'),
            b'}' if allow_interp_braces => out.push(b'}'),
            b'\r' => {
                if self.peek() == Some(b'\n') {
                    self.bump();
                }
                out.push(b'\n');
            }
            b'\n' => out.push(b'\n'),
            b'z' => {
                while let Some(w) = self.peek() {
                    if w.is_ascii_whitespace() {
                        self.bump();
                    } else {
                        break;
                    }
                }
            }
            b'x' => {
                let h1 = self.bump().and_then(hex_val);
                let h2 = self.bump().and_then(hex_val);
                match (h1, h2) {
                    (Some(a), Some(b)) => out.push((a << 4) | b),
                    _ => {
                        return Err(SyntaxError {
                            message: "invalid \\xHH hex escape".into(),
                            span: esc_span,
                        })
                    }
                }
            }
            b'u' => {
                if self.bump() != Some(b'{') {
                    return Err(SyntaxError {
                        message: "expected '{' after \\u".into(),
                        span: esc_span,
                    });
                }
                let mut codepoint: u32 = 0;
                let mut digits = 0;
                while let Some(b) = self.peek() {
                    if b == b'}' {
                        self.bump();
                        break;
                    }
                    if let Some(v) = hex_val(b) {
                        self.bump();
                        codepoint = codepoint
                            .checked_mul(16)
                            .and_then(|c| c.checked_add(v as u32))
                            .ok_or_else(|| SyntaxError {
                                message: "unicode escape overflow".into(),
                                span: esc_span,
                            })?;
                        digits += 1;
                    } else {
                        return Err(SyntaxError {
                            message: "invalid hex digit in \\u{...}".into(),
                            span: esc_span,
                        });
                    }
                }
                if digits == 0 {
                    return Err(SyntaxError {
                        message: "empty \\u{} escape".into(),
                        span: esc_span,
                    });
                }
                if let Some(ch) = char::from_u32(codepoint) {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                } else {
                    return Err(SyntaxError {
                        message: format!("invalid unicode scalar value U+{codepoint:X}"),
                        span: esc_span,
                    });
                }
            }
            d if d.is_ascii_digit() => {
                let mut val: u32 = (d - b'0') as u32;
                for _ in 0..2 {
                    if let Some(nd) = self.peek() {
                        if nd.is_ascii_digit() {
                            self.bump();
                            val = val * 10 + (nd - b'0') as u32;
                        } else {
                            break;
                        }
                    }
                }
                if val > 255 {
                    return Err(SyntaxError {
                        message: format!("decimal escape \\{val} out of byte range (0..=255)"),
                        span: esc_span,
                    });
                }
                out.push(val as u8);
            }
            other => {
                return Err(SyntaxError {
                    message: format!("invalid escape sequence '\\{}'", other as char),
                    span: esc_span,
                });
            }
        }
        Ok(())
    }

    fn read_quoted_string(&mut self, quote: u8, start: Span) -> Result<Vec<u8>, SyntaxError> {
        self.bump(); // opening quote
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\n') | Some(b'\r') => {
                    return Err(SyntaxError {
                        message: "unterminated string literal".into(),
                        span: start,
                    });
                }
                Some(b) if b == quote => {
                    self.bump();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.bump();
                    self.read_escape(&mut out, false)?;
                }
                Some(_) => {
                    out.push(self.bump().unwrap());
                }
            }
        }
    }

    fn read_interp_segment(&mut self, is_start: bool, start: Span) -> Result<TokenKind, SyntaxError> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None | Some(b'\n') | Some(b'\r') => {
                    return Err(SyntaxError {
                        message: "unterminated interpolated string".into(),
                        span: start,
                    });
                }
                Some(b'`') => {
                    self.bump();
                    return Ok(if is_start {
                        TokenKind::InterpSimple(out)
                    } else {
                        TokenKind::InterpEnd(out)
                    });
                }
                Some(b'{') => {
                    self.bump();
                    if self.peek() == Some(b'{') {
                        return Err(SyntaxError {
                            message: "double '{{' is not allowed in Luau interpolated strings; use '\\{'".into(),
                            span: self.span(),
                        });
                    }
                    self.interp_brace_stack.push(0);
                    return Ok(if is_start {
                        TokenKind::InterpBegin(out)
                    } else {
                        TokenKind::InterpMid(out)
                    });
                }
                Some(b'\\') => {
                    self.bump();
                    self.read_escape(&mut out, true)?;
                }
                Some(_) => {
                    out.push(self.bump().unwrap());
                }
            }
        }
    }

    fn read_number(&mut self, start: Span) -> Result<f64, SyntaxError> {
        let begin = self.pos;
        if self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'x' | b'X')) {
            self.bump();
            self.bump();
            let mut int_part: f64 = 0.0;
            let mut has_digits = false;
            while let Some(b) = self.peek() {
                if b == b'_' {
                    self.bump();
                    continue;
                }
                if let Some(v) = hex_val(b) {
                    self.bump();
                    int_part = int_part * 16.0 + (v as f64);
                    has_digits = true;
                } else {
                    break;
                }
            }
            let mut frac_part: f64 = 0.0;
            if self.peek() == Some(b'.') && self.peek_at(1) != Some(b'.') {
                self.bump();
                let mut scale = 1.0 / 16.0;
                while let Some(b) = self.peek() {
                    if b == b'_' {
                        self.bump();
                        continue;
                    }
                    if let Some(v) = hex_val(b) {
                        self.bump();
                        frac_part += (v as f64) * scale;
                        scale /= 16.0;
                        has_digits = true;
                    } else {
                        break;
                    }
                }
            }
            if !has_digits {
                return Err(SyntaxError {
                    message: "malformed hexadecimal number".into(),
                    span: start,
                });
            }
            let mut val = int_part + frac_part;
            if matches!(self.peek(), Some(b'p' | b'P')) {
                self.bump();
                let mut neg = false;
                if self.peek() == Some(b'-') {
                    neg = true;
                    self.bump();
                } else if self.peek() == Some(b'+') {
                    self.bump();
                }
                let mut exp: i32 = 0;
                let mut exp_digits = false;
                while let Some(b) = self.peek() {
                    if b == b'_' {
                        self.bump();
                        continue;
                    }
                    if b.is_ascii_digit() {
                        self.bump();
                        exp = exp.saturating_mul(10).saturating_add((b - b'0') as i32);
                        exp_digits = true;
                    } else {
                        break;
                    }
                }
                if !exp_digits {
                    return Err(SyntaxError {
                        message: "malformed binary exponent in hex float".into(),
                        span: start,
                    });
                }
                if neg {
                    exp = -exp;
                }
                val *= 2f64.powi(exp);
            }
            return Ok(val);
        }

        if self.peek() == Some(b'0') && matches!(self.peek_at(1), Some(b'b' | b'B')) {
            self.bump();
            self.bump();
            let mut val: u64 = 0;
            let mut has_digits = false;
            while let Some(b) = self.peek() {
                match b {
                    b'_' => {
                        self.bump();
                    }
                    b'0' | b'1' => {
                        self.bump();
                        val = val.wrapping_shl(1) | ((b - b'0') as u64);
                        has_digits = true;
                    }
                    _ => break,
                }
            }
            if !has_digits {
                return Err(SyntaxError {
                    message: "malformed binary number".into(),
                    span: start,
                });
            }
            return Ok(val as f64);
        }

        // Decimal integer or float
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() || b == b'_' {
                self.bump();
            } else {
                break;
            }
        }
        if self.peek() == Some(b'.') && self.peek_at(1) != Some(b'.') {
            self.bump();
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() || b == b'_' {
                    self.bump();
                } else {
                    break;
                }
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            let mut exp_digits = false;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() || b == b'_' {
                    if b.is_ascii_digit() {
                        exp_digits = true;
                    }
                    self.bump();
                } else {
                    break;
                }
            }
            if !exp_digits {
                return Err(SyntaxError {
                    message: "malformed exponent in number literal".into(),
                    span: start,
                });
            }
        }

        let raw = &self.bytes[begin..self.pos];
        let mut clean = String::with_capacity(raw.len());
        for &b in raw {
            if b != b'_' {
                clean.push(b as char);
            }
        }
        clean.parse::<f64>().map_err(|_| SyntaxError {
            message: format!("invalid number literal '{clean}'"),
            span: start,
        })
    }

    pub fn next_token(&mut self) -> Result<Token, SyntaxError> {
        self.skip_whitespace_and_comments()?;
        let start = self.span();
        let Some(b) = self.peek() else {
            return Ok(Token {
                kind: TokenKind::Eof,
                span: start,
            });
        };

        let kind = match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                let begin = self.pos;
                while let Some(c) = self.peek() {
                    if c.is_ascii_alphanumeric() || c == b'_' {
                        self.bump();
                    } else {
                        break;
                    }
                }
                let s = std::str::from_utf8(&self.bytes[begin..self.pos]).unwrap();
                TokenKind::from_keyword(s).unwrap_or_else(|| TokenKind::Ident(s.to_string()))
            }
            b'0'..=b'9' => TokenKind::Number(self.read_number(start)?),
            b'.' => {
                if self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
                    TokenKind::Number(self.read_number(start)?)
                } else {
                    self.bump();
                    if self.peek() == Some(b'.') {
                        self.bump();
                        if self.peek() == Some(b'.') {
                            self.bump();
                            TokenKind::DotDotDot
                        } else if self.peek() == Some(b'=') {
                            self.bump();
                            TokenKind::DotDotEq
                        } else {
                            TokenKind::DotDot
                        }
                    } else {
                        TokenKind::Dot
                    }
                }
            }
            b'\'' | b'"' => TokenKind::String(self.read_quoted_string(b, start)?),
            b'`' => {
                self.bump();
                self.read_interp_segment(true, start)?
            }
            b'[' => {
                if let Some(eq_count) = self.check_long_bracket_open() {
                    TokenKind::String(self.read_long_string(eq_count, start, false)?)
                } else {
                    self.bump();
                    TokenKind::LBracket
                }
            }
            b']' => {
                self.bump();
                TokenKind::RBracket
            }
            b'{' => {
                self.bump();
                if let Some(depth) = self.interp_brace_stack.last_mut() {
                    *depth += 1;
                }
                TokenKind::LBrace
            }
            b'}' => {
                self.bump();
                if let Some(&depth) = self.interp_brace_stack.last() {
                    if depth == 0 {
                        self.interp_brace_stack.pop();
                        self.read_interp_segment(false, start)?
                    } else {
                        *self.interp_brace_stack.last_mut().unwrap() -= 1;
                        TokenKind::RBrace
                    }
                } else {
                    TokenKind::RBrace
                }
            }
            b'(' => {
                self.bump();
                TokenKind::LParen
            }
            b')' => {
                self.bump();
                TokenKind::RParen
            }
            b';' => {
                self.bump();
                TokenKind::Semi
            }
            b',' => {
                self.bump();
                TokenKind::Comma
            }
            b':' => {
                self.bump();
                if self.peek() == Some(b':') {
                    self.bump();
                    TokenKind::ColonColon
                } else {
                    TokenKind::Colon
                }
            }
            b'+' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::PlusEq
                } else {
                    TokenKind::Plus
                }
            }
            b'-' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::MinusEq
                } else if self.peek() == Some(b'>') {
                    self.bump();
                    TokenKind::Arrow
                } else {
                    TokenKind::Minus
                }
            }
            b'*' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::StarEq
                } else {
                    TokenKind::Star
                }
            }
            b'/' => {
                self.bump();
                if self.peek() == Some(b'/') {
                    self.bump();
                    if self.peek() == Some(b'=') {
                        self.bump();
                        TokenKind::FloorDivEq
                    } else {
                        TokenKind::FloorDiv
                    }
                } else if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::SlashEq
                } else {
                    TokenKind::Slash
                }
            }
            b'%' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::PercentEq
                } else {
                    TokenKind::Percent
                }
            }
            b'^' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::CaretEq
                } else {
                    TokenKind::Caret
                }
            }
            b'#' => {
                self.bump();
                TokenKind::Hash
            }
            b'=' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::EqEq
                } else {
                    TokenKind::Assign
                }
            }
            b'~' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::TildeEq
                } else {
                    return Err(SyntaxError {
                        message: "expected '=' after '~'".into(),
                        span: start,
                    });
                }
            }
            b'<' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::LtEq
                } else {
                    TokenKind::Lt
                }
            }
            b'>' => {
                self.bump();
                if self.peek() == Some(b'=') {
                    self.bump();
                    TokenKind::GtEq
                } else {
                    TokenKind::Gt
                }
            }
            b'?' => {
                self.bump();
                TokenKind::Question
            }
            b'&' => {
                self.bump();
                TokenKind::Ampersand
            }
            b'|' => {
                self.bump();
                TokenKind::Pipe
            }
            b'@' => {
                self.bump();
                TokenKind::At
            }
            other => {
                return Err(SyntaxError {
                    message: format!("unexpected character '{}'", other as char),
                    span: start,
                });
            }
        };

        Ok(Token { kind, span: start })
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
