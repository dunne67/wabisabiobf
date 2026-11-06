use crate::ast::*;
use crate::lexer::SyntaxError;
use crate::token::{Span, Token, TokenKind};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    pub fn parse_chunk(mut self) -> Result<Block, SyntaxError> {
        let block = self.parse_block()?;
        if self.peek() != &TokenKind::Eof {
            return Err(self.error(format!("unexpected token {:?}", self.peek())));
        }
        Ok(block)
    }

    fn peek(&self) -> &TokenKind {
        &self.tokens[self.pos].kind
    }

    fn peek_at(&self, offset: usize) -> &TokenKind {
        self.tokens
            .get(self.pos + offset)
            .map(|t| &t.kind)
            .unwrap_or(&TokenKind::Eof)
    }

    fn span(&self) -> Span {
        self.tokens[self.pos].span
    }

    fn bump(&mut self) -> Token {
        let tok = self.tokens[self.pos].clone();
        if self.pos + 1 < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    fn eat(&mut self, expected: &TokenKind) -> bool {
        if self.peek() == expected {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: &TokenKind) -> Result<Token, SyntaxError> {
        if self.peek() == expected {
            Ok(self.bump())
        } else {
            Err(self.error(format!("expected {expected:?}, found {:?}", self.peek())))
        }
    }

    fn expect_ident(&mut self) -> Result<String, SyntaxError> {
        match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.bump();
                Ok(s)
            }
            other => Err(self.error(format!("expected identifier, found {other:?}"))),
        }
    }

    fn error(&self, message: impl Into<String>) -> SyntaxError {
        SyntaxError {
            message: message.into(),
            span: self.span(),
        }
    }

    fn is_block_end(&self) -> bool {
        matches!(
            self.peek(),
            TokenKind::End
                | TokenKind::Else
                | TokenKind::Elseif
                | TokenKind::Until
                | TokenKind::Eof
        )
    }

    fn parse_block(&mut self) -> Result<Block, SyntaxError> {
        let mut stmts = Vec::new();
        let mut ret = None;

        while !self.is_block_end() {
            if self.eat(&TokenKind::Semi) {
                continue;
            }
            if self.eat(&TokenKind::Return) {
                let exprs = if self.is_block_end() || self.peek() == &TokenKind::Semi {
                    Vec::new()
                } else {
                    self.parse_expr_list()?
                };
                self.eat(&TokenKind::Semi);
                ret = Some(exprs);
                break;
            }
            if self.eat(&TokenKind::Break) {
                self.eat(&TokenKind::Semi);
                stmts.push(Stmt::Break);
                break;
            }
            if self.is_contextual_continue() {
                self.bump();
                self.eat(&TokenKind::Semi);
                stmts.push(Stmt::Continue);
                break;
            }

            if let Some(stmt) = self.parse_stmt()? {
                stmts.push(stmt);
            }
        }

        Ok(Block { stmts, ret })
    }

    fn is_contextual_continue(&self) -> bool {
        if let TokenKind::Ident(s) = self.peek() {
            if s == "continue" {
                return !matches!(
                    self.peek_at(1),
                    TokenKind::Assign
                        | TokenKind::PlusEq
                        | TokenKind::MinusEq
                        | TokenKind::StarEq
                        | TokenKind::SlashEq
                        | TokenKind::FloorDivEq
                        | TokenKind::PercentEq
                        | TokenKind::CaretEq
                        | TokenKind::DotDotEq
                        | TokenKind::Comma
                        | TokenKind::Dot
                        | TokenKind::Colon
                        | TokenKind::LBracket
                        | TokenKind::LParen
                        | TokenKind::LBrace
                        | TokenKind::String(_)
                );
            }
        }
        false
    }

    fn is_contextual_type_decl(&self) -> bool {
        if let TokenKind::Ident(s) = self.peek() {
            if s == "type" {
                return matches!(self.peek_at(1), TokenKind::Ident(_) | TokenKind::Function);
            }
            if s == "export" {
                if let TokenKind::Ident(next) = self.peek_at(1) {
                    return next == "type";
                }
            }
        }
        false
    }

    fn skip_attributes(&mut self) -> Result<(), SyntaxError> {
        while self.eat(&TokenKind::At) {
            // @native or @[attr1, attr2(...)]
            if self.eat(&TokenKind::LBracket) {
                let mut depth = 1usize;
                while depth > 0 {
                    match self.peek() {
                        TokenKind::LBracket => {
                            depth += 1;
                            self.bump();
                        }
                        TokenKind::RBracket => {
                            depth -= 1;
                            self.bump();
                        }
                        TokenKind::Eof => return Err(self.error("unterminated attribute list")),
                        _ => {
                            self.bump();
                        }
                    }
                }
            } else {
                let _ = self.expect_ident()?;
            }
        }
        Ok(())
    }

    fn parse_stmt(&mut self) -> Result<Option<Stmt>, SyntaxError> {
        if self.peek() == &TokenKind::At {
            self.skip_attributes()?;
        }

        if self.is_contextual_type_decl() {
            self.skip_type_decl()?;
            return Ok(None);
        }

        match self.peek() {
            TokenKind::Local => {
                self.bump();
                if self.peek() == &TokenKind::At {
                    self.skip_attributes()?;
                }
                if self.eat(&TokenKind::Function) {
                    let name = self.expect_ident()?;
                    let func = self.parse_func_body()?;
                    Ok(Some(Stmt::LocalFunction { name, func }))
                } else {
                    let mut names = vec![self.expect_ident()?];
                    if self.eat(&TokenKind::Colon) {
                        self.skip_type()?;
                    }
                    while self.eat(&TokenKind::Comma) {
                        names.push(self.expect_ident()?);
                        if self.eat(&TokenKind::Colon) {
                            self.skip_type()?;
                        }
                    }
                    let values = if self.eat(&TokenKind::Assign) {
                        self.parse_expr_list()?
                    } else {
                        Vec::new()
                    };
                    Ok(Some(Stmt::LocalAssign { names, values }))
                }
            }
            TokenKind::Function => {
                self.bump();
                let name = self.parse_func_name()?;
                let func = self.parse_func_body()?;
                Ok(Some(Stmt::FunctionDef { name, func }))
            }
            TokenKind::Do => {
                self.bump();
                let body = self.parse_block()?;
                self.expect(&TokenKind::End)?;
                Ok(Some(Stmt::Do(body)))
            }
            TokenKind::While => {
                self.bump();
                let cond = self.parse_expr()?;
                self.expect(&TokenKind::Do)?;
                let body = self.parse_block()?;
                self.expect(&TokenKind::End)?;
                Ok(Some(Stmt::While { cond, body }))
            }
            TokenKind::Repeat => {
                self.bump();
                let body = self.parse_block()?;
                self.expect(&TokenKind::Until)?;
                let cond = self.parse_expr()?;
                Ok(Some(Stmt::Repeat { body, cond }))
            }
            TokenKind::If => {
                self.bump();
                let first_cond = self.parse_expr()?;
                self.expect(&TokenKind::Then)?;
                let first_body = self.parse_block()?;
                let mut branches = vec![(first_cond, first_body)];
                while self.eat(&TokenKind::Elseif) {
                    let cond = self.parse_expr()?;
                    self.expect(&TokenKind::Then)?;
                    let body = self.parse_block()?;
                    branches.push((cond, body));
                }
                let else_branch = if self.eat(&TokenKind::Else) {
                    Some(self.parse_block()?)
                } else {
                    None
                };
                self.expect(&TokenKind::End)?;
                Ok(Some(Stmt::If {
                    branches,
                    else_branch,
                }))
            }
            TokenKind::For => {
                self.bump();
                let first_var = self.expect_ident()?;
                if self.eat(&TokenKind::Colon) {
                    self.skip_type()?;
                }
                if self.eat(&TokenKind::Assign) {
                    let start = self.parse_expr()?;
                    self.expect(&TokenKind::Comma)?;
                    let limit = self.parse_expr()?;
                    let step = if self.eat(&TokenKind::Comma) {
                        Some(self.parse_expr()?)
                    } else {
                        None
                    };
                    self.expect(&TokenKind::Do)?;
                    let body = self.parse_block()?;
                    self.expect(&TokenKind::End)?;
                    Ok(Some(Stmt::ForNum {
                        var: first_var,
                        start,
                        limit,
                        step,
                        body,
                    }))
                } else {
                    let mut vars = vec![first_var];
                    while self.eat(&TokenKind::Comma) {
                        vars.push(self.expect_ident()?);
                        if self.eat(&TokenKind::Colon) {
                            self.skip_type()?;
                        }
                    }
                    self.expect(&TokenKind::In)?;
                    let iter_exprs = self.parse_expr_list()?;
                    self.expect(&TokenKind::Do)?;
                    let body = self.parse_block()?;
                    self.expect(&TokenKind::End)?;
                    Ok(Some(Stmt::ForIn {
                        vars,
                        iter_exprs,
                        body,
                    }))
                }
            }
            _ => {
                let expr = self.parse_suffixed_expr()?;
                if matches!(expr, Expr::Call { .. } | Expr::MethodCall { .. }) {
                    return Ok(Some(Stmt::Call(expr)));
                }
                let first_lv = self.expr_to_lvalue(expr)?;
                if let Some(cop) = self.eat_compound_op() {
                    let value = self.parse_expr()?;
                    return Ok(Some(Stmt::CompoundAssign {
                        target: first_lv,
                        op: cop,
                        value,
                    }));
                }
                let mut targets = vec![first_lv];
                while self.eat(&TokenKind::Comma) {
                    let e = self.parse_suffixed_expr()?;
                    targets.push(self.expr_to_lvalue(e)?);
                }
                self.expect(&TokenKind::Assign)?;
                let values = self.parse_expr_list()?;
                Ok(Some(Stmt::Assign { targets, values }))
            }
        }
    }

    fn eat_compound_op(&mut self) -> Option<CompoundOp> {
        let op = match self.peek() {
            TokenKind::PlusEq => CompoundOp::Add,
            TokenKind::MinusEq => CompoundOp::Sub,
            TokenKind::StarEq => CompoundOp::Mul,
            TokenKind::SlashEq => CompoundOp::Div,
            TokenKind::FloorDivEq => CompoundOp::FloorDiv,
            TokenKind::PercentEq => CompoundOp::Mod,
            TokenKind::CaretEq => CompoundOp::Pow,
            TokenKind::DotDotEq => CompoundOp::Concat,
            _ => return None,
        };
        self.bump();
        Some(op)
    }

    fn expr_to_lvalue(&self, expr: Expr) -> Result<LValue, SyntaxError> {
        match expr {
            Expr::Name(s) => Ok(LValue::Name(s)),
            Expr::Index { table, key } => Ok(LValue::Index { table, key }),
            Expr::Field { table, field } => Ok(LValue::Field { table, field }),
            _ => Err(self.error("invalid assignment target")),
        }
    }

    fn parse_func_name(&mut self) -> Result<FuncName, SyntaxError> {
        let base = self.expect_ident()?;
        let mut fields = Vec::new();
        while self.eat(&TokenKind::Dot) {
            fields.push(self.expect_ident()?);
        }
        let method = if self.eat(&TokenKind::Colon) {
            Some(self.expect_ident()?)
        } else {
            None
        };
        Ok(FuncName {
            base,
            fields,
            method,
        })
    }

    fn parse_func_body(&mut self) -> Result<FuncBody, SyntaxError> {
        if self.peek() == &TokenKind::Lt {
            self.skip_generic_type_params()?;
        }
        self.expect(&TokenKind::LParen)?;
        let mut params = Vec::new();
        let mut is_vararg = false;

        if self.peek() != &TokenKind::RParen {
            loop {
                if self.eat(&TokenKind::DotDotDot) {
                    is_vararg = true;
                    if self.eat(&TokenKind::Colon) {
                        self.skip_type()?;
                    }
                    break;
                }
                params.push(self.expect_ident()?);
                if self.eat(&TokenKind::Colon) {
                    self.skip_type()?;
                }
                if !self.eat(&TokenKind::Comma) {
                    break;
                }
            }
        }
        self.expect(&TokenKind::RParen)?;

        if self.eat(&TokenKind::Colon) {
            self.skip_return_type()?;
        }

        let body = self.parse_block()?;
        self.expect(&TokenKind::End)?;
        Ok(FuncBody {
            params,
            is_vararg,
            body,
        })
    }

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>, SyntaxError> {
        let mut list = vec![self.parse_expr()?];
        while self.eat(&TokenKind::Comma) {
            list.push(self.parse_expr()?);
        }
        Ok(list)
    }

    pub fn parse_expr(&mut self) -> Result<Expr, SyntaxError> {
        self.parse_subexpr(0)
    }

    fn parse_subexpr(&mut self, min_prec: u8) -> Result<Expr, SyntaxError> {
        let mut lhs = if let Some(uop) = self.peek_unop() {
            self.bump();
            // Unary prec is 11; '^' is 12 so `-2^2` parses as `-(2^2)`
            let operand = self.parse_subexpr(11)?;
            Expr::Unary {
                op: uop,
                expr: Box::new(operand),
            }
        } else {
            self.parse_assertion_expr()?
        };

        while let Some((bop, left_prec, right_prec)) = self.peek_binop() {
            if left_prec < min_prec {
                break;
            }
            self.bump();
            let rhs = self.parse_subexpr(right_prec)?;
            lhs = Expr::Binary {
                lhs: Box::new(lhs),
                op: bop,
                rhs: Box::new(rhs),
            };
        }

        Ok(lhs)
    }

    fn peek_unop(&self) -> Option<UnOp> {
        match self.peek() {
            TokenKind::Minus => Some(UnOp::Neg),
            TokenKind::Not => Some(UnOp::Not),
            TokenKind::Hash => Some(UnOp::Len),
            _ => None,
        }
    }

    fn peek_binop(&self) -> Option<(BinOp, u8, u8)> {
        match self.peek() {
            TokenKind::Or => Some((BinOp::Or, 1, 2)),
            TokenKind::And => Some((BinOp::And, 3, 4)),
            TokenKind::Lt => Some((BinOp::Lt, 5, 6)),
            TokenKind::Gt => Some((BinOp::Gt, 5, 6)),
            TokenKind::LtEq => Some((BinOp::Le, 5, 6)),
            TokenKind::GtEq => Some((BinOp::Ge, 5, 6)),
            TokenKind::TildeEq => Some((BinOp::Ne, 5, 6)),
            TokenKind::EqEq => Some((BinOp::Eq, 5, 6)),
            // Right-associative '..'
            TokenKind::DotDot => Some((BinOp::Concat, 8, 7)),
            TokenKind::Plus => Some((BinOp::Add, 9, 10)),
            TokenKind::Minus => Some((BinOp::Sub, 9, 10)),
            TokenKind::Star => Some((BinOp::Mul, 10, 11)),
            TokenKind::Slash => Some((BinOp::Div, 10, 11)),
            TokenKind::FloorDiv => Some((BinOp::FloorDiv, 10, 11)),
            TokenKind::Percent => Some((BinOp::Mod, 10, 11)),
            // Right-associative '^', tighter than unary (11)
            TokenKind::Caret => Some((BinOp::Pow, 13, 12)),
            _ => None,
        }
    }

    fn parse_assertion_expr(&mut self) -> Result<Expr, SyntaxError> {
        let expr = self.parse_simple_expr()?;
        while self.eat(&TokenKind::ColonColon) {
            self.skip_type()?;
        }
        Ok(expr)
    }

    fn parse_simple_expr(&mut self) -> Result<Expr, SyntaxError> {
        match self.peek().clone() {
            TokenKind::Nil => {
                self.bump();
                Ok(Expr::Nil)
            }
            TokenKind::False => {
                self.bump();
                Ok(Expr::Bool(false))
            }
            TokenKind::True => {
                self.bump();
                Ok(Expr::Bool(true))
            }
            TokenKind::Number(n) => {
                self.bump();
                Ok(Expr::Number(n))
            }
            TokenKind::String(bytes) => {
                self.bump();
                Ok(Expr::String(bytes))
            }
            TokenKind::InterpSimple(bytes) => {
                self.bump();
                Ok(Expr::String(bytes))
            }
            TokenKind::InterpBegin(first_seg) => {
                self.bump();
                let mut segments = vec![first_seg];
                let mut exprs = Vec::new();
                loop {
                    exprs.push(self.parse_expr()?);
                    match self.peek().clone() {
                        TokenKind::InterpMid(seg) => {
                            self.bump();
                            segments.push(seg);
                        }
                        TokenKind::InterpEnd(seg) => {
                            self.bump();
                            segments.push(seg);
                            break;
                        }
                        other => {
                            return Err(self.error(format!(
                                "expected interpolated string continuation, found {other:?}"
                            )))
                        }
                    }
                }
                Ok(Expr::InterpString { segments, exprs })
            }
            TokenKind::DotDotDot => {
                self.bump();
                Ok(Expr::Vararg)
            }
            TokenKind::LBrace => self.parse_table_expr(),
            TokenKind::At => {
                self.skip_attributes()?;
                self.expect(&TokenKind::Function)?;
                Ok(Expr::Function(self.parse_func_body()?))
            }
            TokenKind::Function => {
                self.bump();
                Ok(Expr::Function(self.parse_func_body()?))
            }
            TokenKind::If => {
                self.bump();
                let cond = self.parse_expr()?;
                self.expect(&TokenKind::Then)?;
                let then_expr = self.parse_expr()?;
                let mut branches = vec![(cond, then_expr)];
                while self.eat(&TokenKind::Elseif) {
                    let c = self.parse_expr()?;
                    self.expect(&TokenKind::Then)?;
                    let t = self.parse_expr()?;
                    branches.push((c, t));
                }
                self.expect(&TokenKind::Else)?;
                let else_expr = self.parse_expr()?;
                Ok(Expr::IfExpr {
                    branches,
                    else_expr: Box::new(else_expr),
                })
            }
            _ => self.parse_suffixed_expr(),
        }
    }

    fn parse_suffixed_expr(&mut self) -> Result<Expr, SyntaxError> {
        let mut expr = match self.peek().clone() {
            TokenKind::Ident(s) => {
                self.bump();
                Expr::Name(s)
            }
            TokenKind::LParen => {
                self.bump();
                let inner = self.parse_expr()?;
                self.expect(&TokenKind::RParen)?;
                Expr::Paren(Box::new(inner))
            }
            other => {
                return Err(self.error(format!("expected expression, found {other:?}")));
            }
        };

        loop {
            match self.peek() {
                TokenKind::Dot => {
                    self.bump();
                    let field = self.expect_ident()?;
                    expr = Expr::Field {
                        table: Box::new(expr),
                        field,
                    };
                }
                TokenKind::LBracket => {
                    self.bump();
                    let key = self.parse_expr()?;
                    self.expect(&TokenKind::RBracket)?;
                    expr = Expr::Index {
                        table: Box::new(expr),
                        key: Box::new(key),
                    };
                }
                TokenKind::Colon => {
                    // Distinguish `:method(args)` vs `::` (ColonColon is its own token)
                    self.bump();
                    let method = self.expect_ident()?;
                    let args = self.parse_call_args()?;
                    expr = Expr::MethodCall {
                        receiver: Box::new(expr),
                        method,
                        args,
                    };
                }
                TokenKind::LParen
                | TokenKind::LBrace
                | TokenKind::String(_)
                | TokenKind::InterpSimple(_) => {
                    let args = self.parse_call_args()?;
                    expr = Expr::Call {
                        func: Box::new(expr),
                        args,
                    };
                }
                _ => break,
            }
        }

        Ok(expr)
    }

    fn parse_call_args(&mut self) -> Result<Vec<Expr>, SyntaxError> {
        match self.peek().clone() {
            TokenKind::LParen => {
                self.bump();
                let args = if self.peek() == &TokenKind::RParen {
                    Vec::new()
                } else {
                    self.parse_expr_list()?
                };
                self.expect(&TokenKind::RParen)?;
                Ok(args)
            }
            TokenKind::LBrace => Ok(vec![self.parse_table_expr()?]),
            TokenKind::String(bytes) | TokenKind::InterpSimple(bytes) => {
                self.bump();
                Ok(vec![Expr::String(bytes)])
            }
            other => Err(self.error(format!("expected function arguments, found {other:?}"))),
        }
    }

    fn parse_table_expr(&mut self) -> Result<Expr, SyntaxError> {
        self.expect(&TokenKind::LBrace)?;
        let mut fields = Vec::new();
        while self.peek() != &TokenKind::RBrace {
            let field = match self.peek() {
                TokenKind::LBracket => {
                    self.bump();
                    let key = self.parse_expr()?;
                    self.expect(&TokenKind::RBracket)?;
                    self.expect(&TokenKind::Assign)?;
                    let value = self.parse_expr()?;
                    TableField::Index { key, value }
                }
                TokenKind::Ident(_) if self.peek_at(1) == &TokenKind::Assign => {
                    let name = self.expect_ident()?;
                    self.expect(&TokenKind::Assign)?;
                    let value = self.parse_expr()?;
                    TableField::Name { field: name, value }
                }
                _ => TableField::Array(self.parse_expr()?),
            };
            fields.push(field);
            if !self.eat(&TokenKind::Comma) && !self.eat(&TokenKind::Semi) {
                break;
            }
        }
        self.expect(&TokenKind::RBrace)?;
        Ok(Expr::Table(fields))
    }

    // ---- Luau Type Annotation Skipping ----

    fn skip_type_decl(&mut self) -> Result<(), SyntaxError> {
        if let TokenKind::Ident(s) = self.peek() {
            if s == "export" {
                self.bump();
            }
        }
        // 'type'
        self.bump();
        if self.eat(&TokenKind::Function) {
            // Luau type function (`type function foo(...) ... end`)
            let _ = self.expect_ident()?;
            let _ = self.parse_func_body()?;
            return Ok(());
        }
        let _ = self.expect_ident()?;
        if self.peek() == &TokenKind::Lt {
            self.skip_generic_type_params()?;
        }
        self.expect(&TokenKind::Assign)?;
        self.skip_type()
    }

    fn skip_generic_type_params(&mut self) -> Result<(), SyntaxError> {
        self.expect(&TokenKind::Lt)?;
        let mut depth = 1usize;
        while depth > 0 {
            match self.peek() {
                TokenKind::Lt => {
                    depth += 1;
                    self.bump();
                }
                TokenKind::Gt => {
                    depth -= 1;
                    self.bump();
                }
                TokenKind::Eof => return Err(self.error("unterminated generic type parameters")),
                _ => {
                    self.bump();
                }
            }
        }
        Ok(())
    }

    fn skip_return_type(&mut self) -> Result<(), SyntaxError> {
        self.skip_type()
    }

    fn skip_type(&mut self) -> Result<(), SyntaxError> {
        // Leading '|' or '&' allowed in Luau multiline union/intersection types
        let _ = self.eat(&TokenKind::Pipe) || self.eat(&TokenKind::Ampersand);
        self.skip_simple_type()?;
        loop {
            if self.eat(&TokenKind::Question) {
                continue;
            }
            if self.eat(&TokenKind::Pipe) || self.eat(&TokenKind::Ampersand) {
                self.skip_simple_type()?;
                continue;
            }
            if self.eat(&TokenKind::Arrow) {
                self.skip_type()?;
                continue;
            }
            break;
        }
        Ok(())
    }

    fn skip_simple_type(&mut self) -> Result<(), SyntaxError> {
        if self.peek() == &TokenKind::Lt {
            self.skip_generic_type_params()?;
        }
        match self.peek().clone() {
            TokenKind::Nil
            | TokenKind::True
            | TokenKind::False
            | TokenKind::String(_) => {
                self.bump();
            }
            TokenKind::DotDotDot => {
                self.bump();
                self.skip_type()?;
            }
            TokenKind::Ident(s) => {
                self.bump();
                if s == "typeof" && self.peek() == &TokenKind::LParen {
                    self.bump();
                    let _ = self.parse_expr()?;
                    self.expect(&TokenKind::RParen)?;
                } else {
                    while self.eat(&TokenKind::Dot) {
                        let _ = self.expect_ident()?;
                    }
                    if self.peek() == &TokenKind::Lt {
                        self.skip_generic_type_params()?;
                    }
                    let _ = self.eat(&TokenKind::DotDotDot);
                }
            }
            TokenKind::LParen => {
                self.bump();
                let mut depth = 1usize;
                while depth > 0 {
                    match self.peek() {
                        TokenKind::LParen => {
                            depth += 1;
                            self.bump();
                        }
                        TokenKind::RParen => {
                            depth -= 1;
                            self.bump();
                        }
                        TokenKind::Eof => return Err(self.error("unterminated parenthesized type")),
                        _ => {
                            self.bump();
                        }
                    }
                }
            }
            TokenKind::LBrace => {
                self.bump();
                let mut depth = 1usize;
                while depth > 0 {
                    match self.peek() {
                        TokenKind::LBrace => {
                            depth += 1;
                            self.bump();
                        }
                        TokenKind::RBrace => {
                            depth -= 1;
                            self.bump();
                        }
                        TokenKind::Eof => return Err(self.error("unterminated table type")),
                        _ => {
                            self.bump();
                        }
                    }
                }
            }
            other => {
                return Err(self.error(format!("expected type annotation, found {other:?}")));
            }
        }
        Ok(())
    }
}
