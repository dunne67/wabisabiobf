#[derive(Debug, Clone)]
pub struct Block {
    pub stmts: Vec<Stmt>,
    pub ret: Option<Vec<Expr>>,
}

#[derive(Debug, Clone)]
pub enum Stmt {
    LocalAssign {
        names: Vec<String>,
        values: Vec<Expr>,
    },
    LocalFunction {
        name: String,
        func: FuncBody,
    },
    FunctionDef {
        name: FuncName,
        func: FuncBody,
    },
    Assign {
        targets: Vec<LValue>,
        values: Vec<Expr>,
    },
    CompoundAssign {
        target: LValue,
        op: CompoundOp,
        value: Expr,
    },
    Call(Expr),
    Do(Block),
    While {
        cond: Expr,
        body: Block,
    },
    Repeat {
        body: Block,
        cond: Expr,
    },
    If {
        branches: Vec<(Expr, Block)>,
        else_branch: Option<Block>,
    },
    ForNum {
        var: String,
        start: Expr,
        limit: Expr,
        step: Option<Expr>,
        body: Block,
    },
    ForIn {
        vars: Vec<String>,
        iter_exprs: Vec<Expr>,
        body: Block,
    },
    Break,
    Continue,
}

#[derive(Debug, Clone)]
pub struct FuncName {
    pub base: String,
    pub fields: Vec<String>,
    pub method: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FuncBody {
    pub params: Vec<String>,
    pub is_vararg: bool,
    pub body: Block,
}

#[derive(Debug, Clone)]
pub enum LValue {
    Name(String),
    Index { table: Box<Expr>, key: Box<Expr> },
    Field { table: Box<Expr>, field: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompoundOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
    Concat,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnOp {
    Neg,
    Not,
    Len,
}

#[derive(Debug, Clone)]
pub enum TableField {
    Index { key: Expr, value: Expr },
    Name { field: String, value: Expr },
    Array(Expr),
}

#[derive(Debug, Clone)]
pub enum Expr {
    Nil,
    Bool(bool),
    Number(f64),
    String(Vec<u8>),
    Vararg,
    Name(String),
    Table(Vec<TableField>),
    Function(FuncBody),
    IfExpr {
        branches: Vec<(Expr, Expr)>,
        else_expr: Box<Expr>,
    },
    InterpString {
        /// Always length `exprs.len() + 1`
        segments: Vec<Vec<u8>>,
        exprs: Vec<Expr>,
    },
    Index {
        table: Box<Expr>,
        key: Box<Expr>,
    },
    Field {
        table: Box<Expr>,
        field: String,
    },
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
    },
    MethodCall {
        receiver: Box<Expr>,
        method: String,
        args: Vec<Expr>,
    },
    Unary {
        op: UnOp,
        expr: Box<Expr>,
    },
    Binary {
        lhs: Box<Expr>,
        op: BinOp,
        rhs: Box<Expr>,
    },
    /// Explicit `(expr)` wrapper: forces multret expressions (`f()`, `...`) to adjust to 1 value!
    Paren(Box<Expr>),
}
