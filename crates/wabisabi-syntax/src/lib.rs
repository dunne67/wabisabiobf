pub mod ast;
pub mod lexer;
pub mod parser;
pub mod token;

use ast::Block;
use lexer::{Lexer, SyntaxError};
use parser::Parser;

pub fn parse_luau(source: &str) -> Result<Block, SyntaxError> {
    let tokens = Lexer::new(source).tokenize()?;
    Parser::new(tokens).parse_chunk()
}
