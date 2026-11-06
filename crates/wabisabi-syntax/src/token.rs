#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    // Literals & Identifiers
    Ident(String),
    Number(f64),
    String(Vec<u8>),

    // Luau Interpolated Strings: `head{e1}mid{e2}tail`
    InterpSimple(Vec<u8>),
    InterpBegin(Vec<u8>),
    InterpMid(Vec<u8>),
    InterpEnd(Vec<u8>),

    // Reserved Keywords
    And,
    Break,
    Do,
    Else,
    Elseif,
    End,
    False,
    For,
    Function,
    If,
    In,
    Local,
    Nil,
    Not,
    Or,
    Repeat,
    Return,
    Then,
    True,
    Until,
    While,

    // Arithmetic & String Operators
    Plus,       // +
    Minus,      // -
    Star,       // *
    Slash,      // /
    FloorDiv,   // //
    Percent,    // %
    Caret,      // ^
    Hash,       // #
    DotDot,     // ..

    // Compound Assignment
    PlusEq,     // +=
    MinusEq,    // -=
    StarEq,     // *=
    SlashEq,    // /=
    FloorDivEq, // //=
    PercentEq,  // %=
    CaretEq,    // ^=
    DotDotEq,   // ..=

    // Relational & Assignment
    EqEq,       // ==
    TildeEq,    // ~=
    LtEq,       // <=
    GtEq,       // >=
    Lt,         // <
    Gt,         // >
    Assign,     // =

    // Punctuation & Type Tokens
    LParen,     // (
    RParen,     // )
    LBrace,     // {
    RBrace,     // }
    LBracket,   // [
    RBracket,   // ]
    Semi,       // ;
    Colon,      // :
    ColonColon, // ::
    Comma,      // ,
    Dot,        // .
    DotDotDot,  // ...
    Arrow,      // ->
    Question,   // ?
    Ampersand,  // &
    Pipe,       // |
    At,         // @

    Eof,
}

impl TokenKind {
    pub fn from_keyword(s: &str) -> Option<TokenKind> {
        match s {
            "and" => Some(TokenKind::And),
            "break" => Some(TokenKind::Break),
            "do" => Some(TokenKind::Do),
            "else" => Some(TokenKind::Else),
            "elseif" => Some(TokenKind::Elseif),
            "end" => Some(TokenKind::End),
            "false" => Some(TokenKind::False),
            "for" => Some(TokenKind::For),
            "function" => Some(TokenKind::Function),
            "if" => Some(TokenKind::If),
            "in" => Some(TokenKind::In),
            "local" => Some(TokenKind::Local),
            "nil" => Some(TokenKind::Nil),
            "not" => Some(TokenKind::Not),
            "or" => Some(TokenKind::Or),
            "repeat" => Some(TokenKind::Repeat),
            "return" => Some(TokenKind::Return),
            "then" => Some(TokenKind::Then),
            "true" => Some(TokenKind::True),
            "until" => Some(TokenKind::Until),
            "while" => Some(TokenKind::While),
            _ => None,
        }
    }
}
