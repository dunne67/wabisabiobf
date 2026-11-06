pub mod ir;
pub mod lower;
pub mod obf;

use ir::IrModule;
use lower::{LowerError, Lowerer};
pub use obf::obfuscate_ir;
use wabisabi_syntax::ast::Block;

pub fn lower_ast(chunk: &Block) -> Result<IrModule, LowerError> {
    Lowerer::lower_chunk(chunk)
}
