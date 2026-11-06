use std::fmt;

pub type Reg = u16;
pub type ConstIdx = u32;
pub type ProtoIdx = u32;
pub type Pc = u32;

#[derive(Debug, Clone)]
pub struct IrModule {
    pub protos: Vec<Proto>,
    pub main_proto: ProtoIdx,
}

#[derive(Debug, Clone)]
pub struct Proto {
    pub num_params: u16,
    pub is_vararg: bool,
    pub max_regs: u16,
    pub constants: Vec<Constant>,
    pub upvalues: Vec<UpvalDesc>,
    pub code: Vec<Instr>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Nil,
    Bool(bool),
    Number(f64),
    String(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpvalDesc {
    /// Captures register `reg` of the immediately enclosing function frame.
    ParentLocal(Reg),
    /// Captures upvalue `uv_idx` of the immediately enclosing function frame.
    ParentUpval(u16),
}

/// Wabi Sabi Custom Register IR.
/// Unlike Lua 5.1 lopcodes, there are no RK-encoded high bits, no mandatory
/// EQ+JMP or LOADBOOL skip pairs, and all control-flow targets are explicit PCs.
#[derive(Debug, Clone)]
pub enum Instr {
    LoadNil { start: Reg, count: u16 },
    LoadBool { dst: Reg, val: bool },
    LoadK { dst: Reg, k: ConstIdx },
    Move { dst: Reg, src: Reg },

    GetGlobal { dst: Reg, name_k: ConstIdx },
    SetGlobal { src: Reg, name_k: ConstIdx },
    GetUpval { dst: Reg, uv: u16 },
    SetUpval { src: Reg, uv: u16 },
    CloseUpvals { from_reg: Reg },
    Closure { dst: Reg, proto: ProtoIdx },

    NewTable { dst: Reg, array_hint: u16 },
    GetTable { dst: Reg, tbl: Reg, key: Reg },
    GetField { dst: Reg, tbl: Reg, key_k: ConstIdx },
    SetTable { tbl: Reg, key: Reg, val: Reg },
    SetField { tbl: Reg, key_k: ConstIdx, val: Reg },
    SetList { tbl: Reg, src_start: Reg, count: u16, array_offset: u32 },
    SetListMultret { tbl: Reg, src_start: Reg, array_offset: u32 },
    SelfMethod { base: Reg, receiver: Reg, method_k: ConstIdx },

    Add { dst: Reg, lhs: Reg, rhs: Reg },
    Sub { dst: Reg, lhs: Reg, rhs: Reg },
    Mul { dst: Reg, lhs: Reg, rhs: Reg },
    Div { dst: Reg, lhs: Reg, rhs: Reg },
    Idiv { dst: Reg, lhs: Reg, rhs: Reg },
    Mod { dst: Reg, lhs: Reg, rhs: Reg },
    Pow { dst: Reg, lhs: Reg, rhs: Reg },
    Concat { dst: Reg, lhs: Reg, rhs: Reg },
    ToString { dst: Reg, src: Reg },

    Neg { dst: Reg, src: Reg },
    Not { dst: Reg, src: Reg },
    Len { dst: Reg, src: Reg },

    CmpEq { dst: Reg, lhs: Reg, rhs: Reg },
    CmpNe { dst: Reg, lhs: Reg, rhs: Reg },
    CmpLt { dst: Reg, lhs: Reg, rhs: Reg },
    CmpLe { dst: Reg, lhs: Reg, rhs: Reg },

    Jump { target: Pc },
    JumpIfTrue { cond: Reg, target: Pc },
    JumpIfFalse { cond: Reg, target: Pc },

    /// `ret_count = None` means MULTRET (sets frame `top`).
    Call { base: Reg, arg_count: u16, ret_count: Option<u16> },
    /// Consumes args `base + 1 .. top`. `ret_count = None` means MULTRET.
    CallMultret { base: Reg, ret_count: Option<u16> },
    /// `count = None` means MULTRET (sets frame `top`).
    Vararg { dst: Reg, count: Option<u16> },

    Return { start: Reg, count: u16 },
    ReturnMultret { start: Reg },

    ForNumPrep { base: Reg, exit_pc: Pc },
    ForNumLoop { base: Reg, body_pc: Pc },

    IterPrep { base: Reg },
    IterLoop { base: Reg, var_count: u16, exit_pc: Pc },

    /// First-execution self-modifying constant load (`OP[pc]` rewrites itself in-place to `LoadK`).
    LoadKInit { dst: Reg, k: ConstIdx },
    /// First-execution self-modifying jump (`OP[pc]` & biased target rewrite in-place to `Jump`).
    JumpInit { target: Pc },
    /// Stateful persistent VM-frame scratch setup (`_sx = dst; _sg = K[k]`), paired with `Commit`.
    KPrep { dst: Reg, k: ConstIdx },
    /// Commits persistent VM-frame scratch (`R[_sx] = _sg`), ignoring its chaff-filled physical operands.
    Commit,
}

impl fmt::Display for IrModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "; Wabi Sabi Custom IR Module (main = proto #{})", self.main_proto)?;
        for (idx, proto) in self.protos.iter().enumerate() {
            writeln!(
                f,
                "\nproto #{idx} (params={}, vararg={}, max_regs={}, upvals={}, consts={}):",
                proto.num_params,
                proto.is_vararg,
                proto.max_regs,
                proto.upvalues.len(),
                proto.constants.len()
            )?;
            for (pc, ins) in proto.code.iter().enumerate() {
                writeln!(f, "  {:04}  {:?}", pc, ins)?;
            }
        }
        Ok(())
    }
}
