use crate::ir::*;
use std::fmt;
use wabisabi_syntax::ast::*;

#[derive(Debug, Clone)]
pub struct LowerError {
    pub message: String,
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LowerError: {}", self.message)
    }
}

impl std::error::Error for LowerError {}

#[derive(Debug, Clone)]
struct LocalVar {
    name: String,
    reg: Reg,
    scope_depth: usize,
    captured: bool,
}

#[derive(Debug, Clone, Copy)]
enum LoopKind {
    Standard { continue_reg_base: Reg },
    Repeat { repeat_scope_depth: usize },
}

#[derive(Debug)]
struct LoopCtx {
    break_reg_base: Reg,
    kind: LoopKind,
    break_jumps: Vec<usize>,
    continue_jumps: Vec<usize>,
}

#[derive(Debug, Clone, Copy)]
enum VarTarget {
    Local(Reg),
    Upval(u16),
    Global(ConstIdx),
}

#[derive(Debug, Clone, Copy)]
enum ResolvedAssignTarget {
    Local(Reg),
    Upval(u16),
    Global(ConstIdx),
    Table { tbl_reg: Reg, key_reg: Reg },
    Field { tbl_reg: Reg, key_k: ConstIdx },
}

struct FuncState {
    num_params: u16,
    is_vararg: bool,
    reg_top: Reg,
    max_regs: Reg,
    scope_depth: usize,
    scope_reg_bases: Vec<Reg>,
    locals: Vec<LocalVar>,
    upvalues: Vec<UpvalDesc>,
    constants: Vec<Constant>,
    code: Vec<Instr>,
    loops: Vec<LoopCtx>,
}

impl FuncState {
    fn new(num_params: u16, is_vararg: bool) -> Self {
        Self {
            num_params,
            is_vararg,
            reg_top: 0,
            max_regs: 1,
            scope_depth: 0,
            scope_reg_bases: vec![0],
            locals: Vec::new(),
            upvalues: Vec::new(),
            constants: Vec::new(),
            code: Vec::new(),
            loops: Vec::new(),
        }
    }

    fn alloc_regs(&mut self, count: u16) -> Result<Reg, LowerError> {
        let base = self.reg_top;
        let next = base
            .checked_add(count)
            .ok_or_else(|| LowerError {
                message: "register overflow (exceeded 65535 registers)".into(),
            })?;
        self.reg_top = next;
        if next > self.max_regs {
            self.max_regs = next;
        }
        Ok(base)
    }

    fn alloc_reg(&mut self) -> Result<Reg, LowerError> {
        self.alloc_regs(1)
    }

    fn push_scope(&mut self) {
        self.scope_depth += 1;
        self.scope_reg_bases.push(self.reg_top);
    }

    fn pop_scope(&mut self, emit_close: bool) {
        let reg_base = self.scope_reg_bases.pop().unwrap_or(0);
        let mut any_captured = false;
        while let Some(last) = self.locals.last() {
            if last.scope_depth == self.scope_depth {
                if last.captured {
                    any_captured = true;
                }
                self.locals.pop();
            } else {
                break;
            }
        }
        if emit_close && any_captured {
            self.emit(Instr::CloseUpvals { from_reg: reg_base });
        }
        self.reg_top = reg_base;
        self.scope_depth -= 1;
    }

    fn declare_local(&mut self, name: String, reg: Reg) {
        self.locals.push(LocalVar {
            name,
            reg,
            scope_depth: self.scope_depth,
            captured: false,
        });
    }

    fn intern_const(&mut self, c: Constant) -> ConstIdx {
        for (idx, existing) in self.constants.iter().enumerate() {
            let same = match (existing, &c) {
                (Constant::Nil, Constant::Nil) => true,
                (Constant::Bool(a), Constant::Bool(b)) => a == b,
                (Constant::Number(a), Constant::Number(b)) => a.to_bits() == b.to_bits(),
                (Constant::String(a), Constant::String(b)) => a == b,
                _ => false,
            };
            if same {
                return idx as ConstIdx;
            }
        }
        let idx = self.constants.len() as ConstIdx;
        self.constants.push(c);
        idx
    }

    fn intern_string(&mut self, s: &[u8]) -> ConstIdx {
        self.intern_const(Constant::String(s.to_vec()))
    }

    fn intern_upval(&mut self, desc: UpvalDesc) -> u16 {
        if let Some(pos) = self.upvalues.iter().position(|u| *u == desc) {
            return pos as u16;
        }
        let idx = self.upvalues.len() as u16;
        self.upvalues.push(desc);
        idx
    }

    fn emit(&mut self, instr: Instr) -> usize {
        let pc = self.code.len();
        self.code.push(instr);
        pc
    }

    fn current_pc(&self) -> Pc {
        self.code.len() as Pc
    }

    fn patch_jump(&mut self, instr_idx: usize, target: Pc) {
        match &mut self.code[instr_idx] {
            Instr::Jump { target: t }
            | Instr::JumpIfTrue { target: t, .. }
            | Instr::JumpIfFalse { target: t, .. } => *t = target,
            Instr::ForNumPrep { exit_pc, .. } | Instr::IterLoop { exit_pc, .. } => {
                *exit_pc = target
            }
            Instr::ForNumLoop { body_pc, .. } => *body_pc = target,
            other => panic!("attempted to patch non-jump instruction: {other:?}"),
        }
    }
}

pub struct Lowerer {
    protos: Vec<Proto>,
    frames: Vec<FuncState>,
}

impl Lowerer {
    pub fn lower_chunk(chunk: &Block) -> Result<IrModule, LowerError> {
        let mut lowerer = Self {
            protos: Vec::new(),
            frames: Vec::new(),
        };
        let main_body = FuncBody {
            params: Vec::new(),
            is_vararg: true,
            body: chunk.clone(),
        };
        let main_proto = lowerer.compile_func(&main_body)?;
        Ok(IrModule {
            protos: lowerer.protos,
            main_proto,
        })
    }

    fn cur(&self) -> &FuncState {
        self.frames.last().unwrap()
    }

    fn cur_mut(&mut self) -> &mut FuncState {
        self.frames.last_mut().unwrap()
    }

    fn compile_func(&mut self, func: &FuncBody) -> Result<ProtoIdx, LowerError> {
        let num_params = func.params.len() as u16;
        let mut state = FuncState::new(num_params, func.is_vararg);
        for param in &func.params {
            let r = state.alloc_reg()?;
            state.declare_local(param.clone(), r);
        }
        self.frames.push(state);

        self.compile_block_contents(&func.body)?;
        // Implicit trailing `return`
        self.cur_mut().emit(Instr::Return { start: 0, count: 0 });

        let finished = self.frames.pop().unwrap();
        let idx = self.protos.len() as ProtoIdx;
        self.protos.push(Proto {
            num_params: finished.num_params,
            is_vararg: finished.is_vararg,
            max_regs: finished.max_regs.max(1),
            constants: finished.constants,
            upvalues: finished.upvalues,
            code: finished.code,
        });
        Ok(idx)
    }

    fn resolve_var(&mut self, name: &str) -> VarTarget {
        let top_idx = self.frames.len() - 1;
        if let Some(local) = self.frames[top_idx]
            .locals
            .iter()
            .rev()
            .find(|l| l.name == name)
        {
            return VarTarget::Local(local.reg);
        }
        if let Some(uv) = self.resolve_upval_in_frame(top_idx, name) {
            return VarTarget::Upval(uv);
        }
        let k = self.cur_mut().intern_string(name.as_bytes());
        VarTarget::Global(k)
    }

    fn resolve_upval_in_frame(&mut self, frame_idx: usize, name: &str) -> Option<u16> {
        if frame_idx == 0 {
            return None;
        }
        let parent_idx = frame_idx - 1;
        if let Some(local) = self.frames[parent_idx]
            .locals
            .iter_mut()
            .rev()
            .find(|l| l.name == name)
        {
            local.captured = true;
            let reg = local.reg;
            let uv = self.frames[frame_idx].intern_upval(UpvalDesc::ParentLocal(reg));
            return Some(uv);
        }
        let parent_uv = self.resolve_upval_in_frame(parent_idx, name)?;
        let uv = self.frames[frame_idx].intern_upval(UpvalDesc::ParentUpval(parent_uv));
        Some(uv)
    }

    fn compile_scoped_block(&mut self, block: &Block) -> Result<(), LowerError> {
        self.cur_mut().push_scope();
        self.compile_block_contents(block)?;
        let emit_close = block.ret.is_none();
        self.cur_mut().pop_scope(emit_close);
        Ok(())
    }

    fn compile_block_contents(&mut self, block: &Block) -> Result<(), LowerError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        if let Some(ret_exprs) = &block.ret {
            self.compile_return(ret_exprs)?;
        }
        Ok(())
    }

    fn compile_return(&mut self, exprs: &[Expr]) -> Result<(), LowerError> {
        if exprs.is_empty() {
            self.cur_mut().emit(Instr::Return { start: 0, count: 0 });
            return Ok(());
        }
        let saved_top = self.cur().reg_top;
        let last_idx = exprs.len() - 1;
        if is_multret_expr(&exprs[last_idx]) {
            let prefix_len = last_idx as u16;
            let base = self.cur_mut().alloc_regs(prefix_len + 1)?;
            for (i, e) in exprs[..last_idx].iter().enumerate() {
                self.compile_expr_into(e, base + i as u16)?;
            }
            self.compile_multret_producer(&exprs[last_idx], base + prefix_len)?;
            self.cur_mut().emit(Instr::ReturnMultret { start: base });
        } else {
            let count = exprs.len() as u16;
            let base = self.cur_mut().alloc_regs(count)?;
            for (i, e) in exprs.iter().enumerate() {
                self.compile_expr_into(e, base + i as u16)?;
            }
            self.cur_mut().emit(Instr::Return { start: base, count });
        }
        self.cur_mut().reg_top = saved_top;
        Ok(())
    }

    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), LowerError> {
        match stmt {
            Stmt::LocalAssign { names, values } => {
                let count = names.len() as u16;
                let base = self.cur_mut().alloc_regs(count)?;
                self.compile_expr_list_fixed(values, base, count)?;
                for (i, name) in names.iter().enumerate() {
                    self.cur_mut().declare_local(name.clone(), base + i as u16);
                }
                Ok(())
            }
            Stmt::LocalFunction { name, func } => {
                let dst = self.cur_mut().alloc_reg()?;
                self.cur_mut().declare_local(name.clone(), dst);
                let proto = self.compile_func(func)?;
                self.cur_mut().emit(Instr::Closure { dst, proto });
                Ok(())
            }
            Stmt::FunctionDef { name, func } => {
                let mut body = func.clone();
                if name.method.is_some() {
                    body.params.insert(0, "self".to_string());
                }
                let proto = self.compile_func(&body)?;
                let saved_top = self.cur().reg_top;
                let closure_reg = self.cur_mut().alloc_reg()?;
                self.cur_mut().emit(Instr::Closure {
                    dst: closure_reg,
                    proto,
                });

                if name.fields.is_empty() && name.method.is_none() {
                    self.store_var(&name.base, closure_reg);
                } else {
                    let tbl_reg = self.cur_mut().alloc_reg()?;
                    self.load_var(&name.base, tbl_reg);
                    let total_chain: Vec<&str> = name
                        .fields
                        .iter()
                        .map(|s| s.as_str())
                        .chain(name.method.iter().map(|s| s.as_str()))
                        .collect();
                    for &field in &total_chain[..total_chain.len() - 1] {
                        let k = self.cur_mut().intern_string(field.as_bytes());
                        self.cur_mut().emit(Instr::GetField {
                            dst: tbl_reg,
                            tbl: tbl_reg,
                            key_k: k,
                        });
                    }
                    let last_field = total_chain[total_chain.len() - 1];
                    let k = self.cur_mut().intern_string(last_field.as_bytes());
                    self.cur_mut().emit(Instr::SetField {
                        tbl: tbl_reg,
                        key_k: k,
                        val: closure_reg,
                    });
                }
                self.cur_mut().reg_top = saved_top;
                Ok(())
            }
            Stmt::Assign { targets, values } => {
                let saved_top = self.cur().reg_top;
                // 1. Evaluate LHS table/key addresses left-to-right BEFORE RHS
                //    (keeping direct local register refs just like Luau's Compiler.cpp)
                let mut resolved = Vec::with_capacity(targets.len());
                for t in targets {
                    resolved.push(self.prepare_lvalue(t)?);
                }
                // 2. Evaluate RHS values into temporary registers
                let count = targets.len() as u16;
                let val_base = self.cur_mut().alloc_regs(count)?;
                self.compile_expr_list_fixed(values, val_base, count)?;
                // 3. Store left-to-right, snapshotting any local register referenced by a later LHS table/key
                for i in 0..resolved.len() {
                    if let ResolvedAssignTarget::Local(r) = resolved[i] {
                        let used_later = resolved[i + 1..].iter().any(|later| match *later {
                            ResolvedAssignTarget::Table { tbl_reg, key_reg } => {
                                tbl_reg == r || key_reg == r
                            }
                            ResolvedAssignTarget::Field { tbl_reg, .. } => tbl_reg == r,
                            _ => false,
                        });
                        if used_later {
                            let bak = self.cur_mut().alloc_reg()?;
                            self.cur_mut().emit(Instr::Move { dst: bak, src: r });
                            for later in &mut resolved[i + 1..] {
                                match later {
                                    ResolvedAssignTarget::Table { tbl_reg, key_reg } => {
                                        if *tbl_reg == r {
                                            *tbl_reg = bak;
                                        }
                                        if *key_reg == r {
                                            *key_reg = bak;
                                        }
                                    }
                                    ResolvedAssignTarget::Field { tbl_reg, .. } => {
                                        if *tbl_reg == r {
                                            *tbl_reg = bak;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    self.finish_lvalue_store(resolved[i], val_base + i as u16);
                }
                self.cur_mut().reg_top = saved_top;
                Ok(())
            }
            Stmt::CompoundAssign { target, op, value } => {
                let saved_top = self.cur().reg_top;
                // Evaluate target address ONCE!
                let resolved = self.prepare_lvalue(target)?;
                let lhs_reg = self.cur_mut().alloc_reg()?;
                self.read_prepared_lvalue(resolved, lhs_reg);
                let rhs_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(value, rhs_reg)?;
                let res_reg = lhs_reg;
                let bin_instr = match op {
                    CompoundOp::Add => Instr::Add { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Sub => Instr::Sub { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Mul => Instr::Mul { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Div => Instr::Div { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::FloorDiv => Instr::Idiv { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Mod => Instr::Mod { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Pow => Instr::Pow { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                    CompoundOp::Concat => Instr::Concat { dst: res_reg, lhs: lhs_reg, rhs: rhs_reg },
                };
                self.cur_mut().emit(bin_instr);
                self.finish_lvalue_store(resolved, res_reg);
                self.cur_mut().reg_top = saved_top;
                Ok(())
            }
            Stmt::Call(call_expr) => {
                let saved_top = self.cur().reg_top;
                let base = self.cur_mut().alloc_reg()?;
                self.compile_call_with_results(call_expr, base, Some(0))?;
                self.cur_mut().reg_top = saved_top;
                Ok(())
            }
            Stmt::Do(body) => self.compile_scoped_block(body),
            Stmt::While { cond, body } => {
                let loop_start = self.cur().current_pc();
                let saved_top = self.cur().reg_top;
                let cond_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(cond, cond_reg)?;
                let exit_jmp = self.cur_mut().emit(Instr::JumpIfFalse {
                    cond: cond_reg,
                    target: 0,
                });
                self.cur_mut().reg_top = saved_top;

                let break_reg_base = self.cur().reg_top;
                self.cur_mut().loops.push(LoopCtx {
                    break_reg_base,
                    kind: LoopKind::Standard {
                        continue_reg_base: break_reg_base,
                    },
                    break_jumps: Vec::new(),
                    continue_jumps: Vec::new(),
                });

                self.compile_scoped_block(body)?;
                self.cur_mut().emit(Instr::Jump { target: loop_start });

                let exit_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(exit_jmp, exit_pc);
                let loop_ctx = self.cur_mut().loops.pop().unwrap();
                for bj in loop_ctx.break_jumps {
                    self.cur_mut().patch_jump(bj, exit_pc);
                }
                for cj in loop_ctx.continue_jumps {
                    self.cur_mut().patch_jump(cj, loop_start);
                }
                Ok(())
            }
            Stmt::Repeat { body, cond } => {
                let loop_start = self.cur().current_pc();
                let repeat_reg_base = self.cur().reg_top;

                self.cur_mut().push_scope();
                let repeat_scope_depth = self.cur().scope_depth;
                self.cur_mut().loops.push(LoopCtx {
                    break_reg_base: repeat_reg_base,
                    kind: LoopKind::Repeat { repeat_scope_depth },
                    break_jumps: Vec::new(),
                    continue_jumps: Vec::new(),
                });

                self.compile_block_contents(body)?;

                let cond_pc = self.cur().current_pc();
                let loop_ctx_continues = self.cur().loops.last().unwrap().continue_jumps.clone();
                for cj in loop_ctx_continues {
                    self.cur_mut().patch_jump(cj, cond_pc);
                }

                let cond_saved_top = self.cur().reg_top;
                let cond_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(cond, cond_reg)?;
                let cond_true_jmp = self.cur_mut().emit(Instr::JumpIfTrue {
                    cond: cond_reg,
                    target: 0,
                });
                self.cur_mut().reg_top = cond_saved_top;

                // False path: close repeat-body upvalues before next iteration!
                let any_captured = self
                    .cur()
                    .locals
                    .iter()
                    .any(|l| l.scope_depth >= repeat_scope_depth && l.captured);
                if any_captured {
                    self.cur_mut().emit(Instr::CloseUpvals {
                        from_reg: repeat_reg_base,
                    });
                }
                self.cur_mut().emit(Instr::Jump { target: loop_start });

                // True path: close repeat-body upvalues and exit!
                let true_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(cond_true_jmp, true_pc);
                self.cur_mut().pop_scope(true);

                let exit_pc = self.cur().current_pc();
                let loop_ctx = self.cur_mut().loops.pop().unwrap();
                for bj in loop_ctx.break_jumps {
                    self.cur_mut().patch_jump(bj, exit_pc);
                }
                Ok(())
            }
            Stmt::If {
                branches,
                else_branch,
            } => {
                let mut end_jumps = Vec::new();
                for (cond, body) in branches {
                    let saved_top = self.cur().reg_top;
                    let cond_reg = self.cur_mut().alloc_reg()?;
                    self.compile_expr_into(cond, cond_reg)?;
                    let false_jmp = self.cur_mut().emit(Instr::JumpIfFalse {
                        cond: cond_reg,
                        target: 0,
                    });
                    self.cur_mut().reg_top = saved_top;

                    self.compile_scoped_block(body)?;
                    end_jumps.push(self.cur_mut().emit(Instr::Jump { target: 0 }));

                    let next_pc = self.cur().current_pc();
                    self.cur_mut().patch_jump(false_jmp, next_pc);
                }
                if let Some(else_blk) = else_branch {
                    self.compile_scoped_block(else_blk)?;
                }
                let end_pc = self.cur().current_pc();
                for ej in end_jumps {
                    self.cur_mut().patch_jump(ej, end_pc);
                }
                Ok(())
            }
            Stmt::ForNum {
                var,
                start,
                limit,
                step,
                body,
            } => {
                let saved_outer = self.cur().reg_top;
                self.cur_mut().push_scope();
                // base+0 = internal idx, base+1 = limit, base+2 = step, base+3 = loop var
                let base = self.cur_mut().alloc_regs(4)?;
                self.compile_expr_into(start, base)?;
                self.compile_expr_into(limit, base + 1)?;
                if let Some(step_expr) = step {
                    self.compile_expr_into(step_expr, base + 2)?;
                } else {
                    let k_one = self.cur_mut().intern_const(Constant::Number(1.0));
                    self.cur_mut().emit(Instr::LoadK {
                        dst: base + 2,
                        k: k_one,
                    });
                }
                self.cur_mut().declare_local(var.clone(), base + 3);

                let prep_idx = self.cur_mut().emit(Instr::ForNumPrep { base, exit_pc: 0 });
                let body_pc = self.cur().current_pc();

                self.cur_mut().loops.push(LoopCtx {
                    break_reg_base: base + 3,
                    kind: LoopKind::Standard {
                        continue_reg_base: base + 3,
                    },
                    break_jumps: Vec::new(),
                    continue_jumps: Vec::new(),
                });

                self.compile_scoped_block(body)?;

                let step_pc = self.cur().current_pc();
                self.cur_mut().emit(Instr::ForNumLoop { base, body_pc });
                let exit_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(prep_idx, exit_pc);

                let loop_ctx = self.cur_mut().loops.pop().unwrap();
                for bj in loop_ctx.break_jumps {
                    self.cur_mut().patch_jump(bj, exit_pc);
                }
                for cj in loop_ctx.continue_jumps {
                    self.cur_mut().patch_jump(cj, step_pc);
                }

                self.cur_mut().pop_scope(false);
                self.cur_mut().reg_top = saved_outer;
                Ok(())
            }
            Stmt::ForIn {
                vars,
                iter_exprs,
                body,
            } => {
                let saved_outer = self.cur().reg_top;
                self.cur_mut().push_scope();
                let var_count = vars.len() as u16;
                // base+0 = gen, base+1 = state, base+2 = ctrl, base+3.. = vars
                let base = self.cur_mut().alloc_regs(3 + var_count)?;
                self.compile_expr_list_fixed(iter_exprs, base, 3)?;
                for (i, v) in vars.iter().enumerate() {
                    self.cur_mut().declare_local(v.clone(), base + 3 + i as u16);
                }

                self.cur_mut().emit(Instr::IterPrep { base });
                let loop_head_pc = self.cur().current_pc();
                let iter_idx = self.cur_mut().emit(Instr::IterLoop {
                    base,
                    var_count,
                    exit_pc: 0,
                });

                self.cur_mut().loops.push(LoopCtx {
                    break_reg_base: base + 3,
                    kind: LoopKind::Standard {
                        continue_reg_base: base + 3,
                    },
                    break_jumps: Vec::new(),
                    continue_jumps: Vec::new(),
                });

                self.compile_scoped_block(body)?;

                let continue_pc = self.cur().current_pc();
                // Close captured loop variables per iteration before advancing iterator
                if self
                    .cur()
                    .locals
                    .iter()
                    .any(|l| l.reg >= base + 3 && l.captured)
                {
                    self.cur_mut().emit(Instr::CloseUpvals { from_reg: base + 3 });
                }
                self.cur_mut().emit(Instr::Jump {
                    target: loop_head_pc,
                });

                let exit_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(iter_idx, exit_pc);

                let loop_ctx = self.cur_mut().loops.pop().unwrap();
                for bj in loop_ctx.break_jumps {
                    self.cur_mut().patch_jump(bj, exit_pc);
                }
                for cj in loop_ctx.continue_jumps {
                    self.cur_mut().patch_jump(cj, continue_pc);
                }

                self.cur_mut().pop_scope(false);
                self.cur_mut().reg_top = saved_outer;
                Ok(())
            }
            Stmt::Break => {
                let Some(loop_ctx) = self.cur().loops.last() else {
                    return Err(LowerError {
                        message: "'break' outside of loop".into(),
                    });
                };
                let break_reg_base = loop_ctx.break_reg_base;
                if self.cur().reg_top > break_reg_base {
                    self.cur_mut().emit(Instr::CloseUpvals {
                        from_reg: break_reg_base,
                    });
                }
                let jmp = self.cur_mut().emit(Instr::Jump { target: 0 });
                self.cur_mut().loops.last_mut().unwrap().break_jumps.push(jmp);
                Ok(())
            }
            Stmt::Continue => {
                let Some(loop_ctx) = self.cur().loops.last() else {
                    return Err(LowerError {
                        message: "'continue' outside of loop".into(),
                    });
                };
                let close_base = match loop_ctx.kind {
                    LoopKind::Standard { continue_reg_base } => continue_reg_base,
                    LoopKind::Repeat { repeat_scope_depth } => {
                        // Keep top-level repeat locals open for `until cond`, close inner block locals!
                        self.cur()
                            .scope_reg_bases
                            .get(repeat_scope_depth + 1)
                            .copied()
                            .unwrap_or(self.cur().reg_top)
                    }
                };
                if self.cur().reg_top > close_base {
                    self.cur_mut().emit(Instr::CloseUpvals {
                        from_reg: close_base,
                    });
                }
                let jmp = self.cur_mut().emit(Instr::Jump { target: 0 });
                self.cur_mut()
                    .loops
                    .last_mut()
                    .unwrap()
                    .continue_jumps
                    .push(jmp);
                Ok(())
            }
        }
    }

    fn compile_lvalue_subexpr(&mut self, expr: &Expr) -> Result<Reg, LowerError> {
        if let Expr::Name(name) = expr {
            if let VarTarget::Local(r) = self.resolve_var(name) {
                return Ok(r);
            }
        }
        let r = self.cur_mut().alloc_reg()?;
        self.compile_expr_into(expr, r)?;
        Ok(r)
    }

    fn prepare_lvalue(&mut self, lv: &LValue) -> Result<ResolvedAssignTarget, LowerError> {
        match lv {
            LValue::Name(name) => Ok(match self.resolve_var(name) {
                VarTarget::Local(r) => ResolvedAssignTarget::Local(r),
                VarTarget::Upval(u) => ResolvedAssignTarget::Upval(u),
                VarTarget::Global(k) => ResolvedAssignTarget::Global(k),
            }),
            LValue::Index { table, key } => {
                let tbl_reg = self.compile_lvalue_subexpr(table)?;
                let key_reg = self.compile_lvalue_subexpr(key)?;
                Ok(ResolvedAssignTarget::Table { tbl_reg, key_reg })
            }
            LValue::Field { table, field } => {
                let tbl_reg = self.compile_lvalue_subexpr(table)?;
                let key_k = self.cur_mut().intern_string(field.as_bytes());
                Ok(ResolvedAssignTarget::Field { tbl_reg, key_k })
            }
        }
    }

    fn read_prepared_lvalue(&mut self, target: ResolvedAssignTarget, dst: Reg) {
        match target {
            ResolvedAssignTarget::Local(r) => {
                if dst != r {
                    self.cur_mut().emit(Instr::Move { dst, src: r });
                }
            }
            ResolvedAssignTarget::Upval(uv) => {
                self.cur_mut().emit(Instr::GetUpval { dst, uv });
            }
            ResolvedAssignTarget::Global(name_k) => {
                self.cur_mut().emit(Instr::GetGlobal { dst, name_k });
            }
            ResolvedAssignTarget::Table { tbl_reg, key_reg } => {
                self.cur_mut().emit(Instr::GetTable {
                    dst,
                    tbl: tbl_reg,
                    key: key_reg,
                });
            }
            ResolvedAssignTarget::Field { tbl_reg, key_k } => {
                self.cur_mut().emit(Instr::GetField {
                    dst,
                    tbl: tbl_reg,
                    key_k,
                });
            }
        }
    }

    fn finish_lvalue_store(&mut self, target: ResolvedAssignTarget, val_reg: Reg) {
        match target {
            ResolvedAssignTarget::Local(r) => {
                if r != val_reg {
                    self.cur_mut().emit(Instr::Move { dst: r, src: val_reg });
                }
            }
            ResolvedAssignTarget::Upval(uv) => {
                self.cur_mut().emit(Instr::SetUpval { src: val_reg, uv });
            }
            ResolvedAssignTarget::Global(name_k) => {
                self.cur_mut().emit(Instr::SetGlobal {
                    src: val_reg,
                    name_k,
                });
            }
            ResolvedAssignTarget::Table { tbl_reg, key_reg } => {
                self.cur_mut().emit(Instr::SetTable {
                    tbl: tbl_reg,
                    key: key_reg,
                    val: val_reg,
                });
            }
            ResolvedAssignTarget::Field { tbl_reg, key_k } => {
                self.cur_mut().emit(Instr::SetField {
                    tbl: tbl_reg,
                    key_k,
                    val: val_reg,
                });
            }
        }
    }

    fn load_var(&mut self, name: &str, dst: Reg) {
        match self.resolve_var(name) {
            VarTarget::Local(r) => {
                if dst != r {
                    self.cur_mut().emit(Instr::Move { dst, src: r });
                }
            }
            VarTarget::Upval(uv) => {
                self.cur_mut().emit(Instr::GetUpval { dst, uv });
            }
            VarTarget::Global(name_k) => {
                self.cur_mut().emit(Instr::GetGlobal { dst, name_k });
            }
        }
    }

    fn store_var(&mut self, name: &str, src: Reg) {
        match self.resolve_var(name) {
            VarTarget::Local(r) => {
                if r != src {
                    self.cur_mut().emit(Instr::Move { dst: r, src });
                }
            }
            VarTarget::Upval(uv) => {
                self.cur_mut().emit(Instr::SetUpval { src, uv });
            }
            VarTarget::Global(name_k) => {
                self.cur_mut().emit(Instr::SetGlobal { src, name_k });
            }
        }
    }

    /// Evaluates `exprs` into `base .. base + needed`.
    /// Handles nil padding when fewer values than `needed`, multret expansion on the last
    /// expression, and side-effect evaluation when `exprs.len() > needed`.
    fn compile_expr_list_fixed(
        &mut self,
        exprs: &[Expr],
        base: Reg,
        needed: u16,
    ) -> Result<(), LowerError> {
        if exprs.is_empty() {
            if needed > 0 {
                self.cur_mut().emit(Instr::LoadNil {
                    start: base,
                    count: needed,
                });
            }
            return Ok(());
        }

        let n_exprs = exprs.len();
        let needed_usize = needed as usize;

        if n_exprs >= needed_usize {
            for (i, e) in exprs.iter().enumerate() {
                if i < needed_usize {
                    self.compile_expr_into(e, base + i as u16)?;
                } else {
                    // Evaluate extra expressions for side effects
                    let saved = self.cur().reg_top;
                    let tmp = self.cur_mut().alloc_reg()?;
                    self.compile_expr_into(e, tmp)?;
                    self.cur_mut().reg_top = saved;
                }
            }
            return Ok(());
        }

        // Fewer expressions than `needed`: last expression may expand to `tail_needed` results!
        let last_idx = n_exprs - 1;
        for (i, e) in exprs[..last_idx].iter().enumerate() {
            self.compile_expr_into(e, base + i as u16)?;
        }
        let tail_start = base + last_idx as u16;
        let tail_needed = needed - last_idx as u16;
        let last_expr = &exprs[last_idx];

        match last_expr {
            Expr::Call { .. } | Expr::MethodCall { .. } => {
                let saved = self.cur().reg_top;
                // Ensure `reg_top` is at least `tail_start + tail_needed` while compiling the call
                if self.cur().reg_top < tail_start + tail_needed {
                    self.cur_mut().reg_top = tail_start + tail_needed;
                    if self.cur().reg_top > self.cur().max_regs {
                        self.cur_mut().max_regs = self.cur().reg_top;
                    }
                }
                self.compile_call_with_results(last_expr, tail_start, Some(tail_needed))?;
                self.cur_mut().reg_top = saved;
            }
            Expr::Vararg => {
                if !self.cur().is_vararg {
                    return Err(LowerError {
                        message: "cannot use '...' outside a vararg function".into(),
                    });
                }
                self.cur_mut().emit(Instr::Vararg {
                    dst: tail_start,
                    count: Some(tail_needed),
                });
            }
            _ => {
                self.compile_expr_into(last_expr, tail_start)?;
                if tail_needed > 1 {
                    self.cur_mut().emit(Instr::LoadNil {
                        start: tail_start + 1,
                        count: tail_needed - 1,
                    });
                }
            }
        }
        Ok(())
    }

    fn compile_multret_producer(&mut self, expr: &Expr, dst_base: Reg) -> Result<(), LowerError> {
        match expr {
            Expr::Call { .. } | Expr::MethodCall { .. } => {
                let saved = self.cur().reg_top;
                debug_assert!(saved <= dst_base + 1);
                self.cur_mut().reg_top = dst_base;
                self.compile_call_with_results(expr, dst_base, None)?;
                self.cur_mut().reg_top = saved;
                Ok(())
            }
            Expr::Vararg => {
                if !self.cur().is_vararg {
                    return Err(LowerError {
                        message: "cannot use '...' outside a vararg function".into(),
                    });
                }
                self.cur_mut().emit(Instr::Vararg {
                    dst: dst_base,
                    count: None,
                });
                Ok(())
            }
            _ => unreachable!("compile_multret_producer called on non-multret expr"),
        }
    }

    /// Evaluates `call_expr` (`Call` or `MethodCall`) using `call_base` as the callee slot.
    /// Places `ret_count` results starting at `call_base` (or sets `top` if `None`).
    fn compile_call_with_results(
        &mut self,
        call_expr: &Expr,
        call_base: Reg,
        ret_count: Option<u16>,
    ) -> Result<(), LowerError> {
        let saved_top = self.cur().reg_top;
        // Arguments MUST live at `call_base + 1 ..` without clobbering lower registers!
        let work_base = if saved_top <= call_base {
            call_base
        } else {
            // If `call_base` is below `saved_top` (e.g. compiling directly into an existing local slot),
            // stage the call frame at `saved_top`, then move fixed results back down if needed!
            saved_top
        };

        // Reserve callee slot (`work_base`)
        self.cur_mut().reg_top = work_base;
        let _ = self.cur_mut().alloc_reg()?;

        match call_expr {
            Expr::Call { func, args } => {
                self.compile_expr_into(func, work_base)?;
                self.emit_call_args_and_invoke(work_base, 0, args, ret_count)?;
            }
            Expr::MethodCall {
                receiver,
                method,
                args,
            } => {
                // Self slot is `work_base + 1`
                let self_slot = self.cur_mut().alloc_reg()?;
                debug_assert_eq!(self_slot, work_base + 1);
                let recv_tmp = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(receiver, recv_tmp)?;
                let method_k = self.cur_mut().intern_string(method.as_bytes());
                self.cur_mut().emit(Instr::SelfMethod {
                    base: work_base,
                    receiver: recv_tmp,
                    method_k,
                });
                // Reclaim `recv_tmp` before evaluating args into `work_base + 2 ..`
                self.cur_mut().reg_top = work_base + 2;
                self.emit_call_args_and_invoke(work_base, 1, args, ret_count)?;
            }
            _ => unreachable!(),
        }

        if work_base != call_base {
            match ret_count {
                Some(0) => {}
                Some(n) => {
                    for i in 0..n {
                        self.cur_mut().emit(Instr::Move {
                            dst: call_base + i,
                            src: work_base + i,
                        });
                    }
                }
                None => {
                    panic!("multret call must always be compiled at top of stack (`call_base >= reg_top`)");
                }
            }
        }

        self.cur_mut().reg_top = saved_top;
        Ok(())
    }

    fn emit_call_args_and_invoke(
        &mut self,
        work_base: Reg,
        self_offset: u16,
        args: &[Expr],
        ret_count: Option<u16>,
    ) -> Result<(), LowerError> {
        if args.is_empty() {
            self.cur_mut().emit(Instr::Call {
                base: work_base,
                arg_count: self_offset,
                ret_count,
            });
            return Ok(());
        }

        let last_idx = args.len() - 1;
        if is_multret_expr(&args[last_idx]) {
            let fixed = self.cur_mut().alloc_regs(last_idx as u16)?;
            debug_assert_eq!(fixed, work_base + 1 + self_offset);
            for (i, a) in args[..last_idx].iter().enumerate() {
                self.compile_expr_into(a, fixed + i as u16)?;
            }
            let mult_slot = self.cur_mut().alloc_reg()?;
            self.compile_multret_producer(&args[last_idx], mult_slot)?;
            self.cur_mut().emit(Instr::CallMultret {
                base: work_base,
                ret_count,
            });
        } else {
            let arg_slots = self.cur_mut().alloc_regs(args.len() as u16)?;
            debug_assert_eq!(arg_slots, work_base + 1 + self_offset);
            for (i, a) in args.iter().enumerate() {
                self.compile_expr_into(a, arg_slots + i as u16)?;
            }
            self.cur_mut().emit(Instr::Call {
                base: work_base,
                arg_count: self_offset + args.len() as u16,
                ret_count,
            });
        }
        Ok(())
    }

    fn compile_expr_into(&mut self, expr: &Expr, dst: Reg) -> Result<(), LowerError> {
        let saved_top = self.cur().reg_top;
        if dst >= self.cur().reg_top {
            self.cur_mut().reg_top = dst + 1;
            if self.cur().reg_top > self.cur().max_regs {
                self.cur_mut().max_regs = self.cur().reg_top;
            }
        }

        match expr {
            Expr::Nil => {
                self.cur_mut().emit(Instr::LoadNil {
                    start: dst,
                    count: 1,
                });
            }
            Expr::Bool(val) => {
                self.cur_mut().emit(Instr::LoadBool { dst, val: *val });
            }
            Expr::Number(n) => {
                let k = self.cur_mut().intern_const(Constant::Number(*n));
                self.cur_mut().emit(Instr::LoadK { dst, k });
            }
            Expr::String(bytes) => {
                let k = self.cur_mut().intern_const(Constant::String(bytes.clone()));
                self.cur_mut().emit(Instr::LoadK { dst, k });
            }
            Expr::Vararg => {
                if !self.cur().is_vararg {
                    return Err(LowerError {
                        message: "cannot use '...' outside a vararg function".into(),
                    });
                }
                self.cur_mut().emit(Instr::Vararg {
                    dst,
                    count: Some(1),
                });
            }
            Expr::Name(name) => {
                self.load_var(name, dst);
            }
            Expr::Paren(inner) => {
                self.compile_expr_into(inner, dst)?;
            }
            Expr::Function(func_body) => {
                let proto = self.compile_func(func_body)?;
                self.cur_mut().emit(Instr::Closure { dst, proto });
            }
            Expr::Index { table, key } => {
                let tbl_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(table, tbl_reg)?;
                let key_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(key, key_reg)?;
                self.cur_mut().emit(Instr::GetTable {
                    dst,
                    tbl: tbl_reg,
                    key: key_reg,
                });
            }
            Expr::Field { table, field } => {
                let tbl_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(table, tbl_reg)?;
                let key_k = self.cur_mut().intern_string(field.as_bytes());
                self.cur_mut().emit(Instr::GetField {
                    dst,
                    tbl: tbl_reg,
                    key_k,
                });
            }
            Expr::Call { .. } | Expr::MethodCall { .. } => {
                self.compile_call_with_results(expr, dst, Some(1))?;
            }
            Expr::Unary { op, expr: inner } => {
                let src = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(inner, src)?;
                let instr = match op {
                    UnOp::Neg => Instr::Neg { dst, src },
                    UnOp::Not => Instr::Not { dst, src },
                    UnOp::Len => Instr::Len { dst, src },
                };
                self.cur_mut().emit(instr);
            }
            Expr::Binary {
                lhs,
                op: BinOp::And,
                rhs,
            } => {
                self.compile_expr_into(lhs, dst)?;
                let skip_jmp = self.cur_mut().emit(Instr::JumpIfFalse {
                    cond: dst,
                    target: 0,
                });
                self.compile_expr_into(rhs, dst)?;
                let end_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(skip_jmp, end_pc);
            }
            Expr::Binary {
                lhs,
                op: BinOp::Or,
                rhs,
            } => {
                self.compile_expr_into(lhs, dst)?;
                let skip_jmp = self.cur_mut().emit(Instr::JumpIfTrue {
                    cond: dst,
                    target: 0,
                });
                self.compile_expr_into(rhs, dst)?;
                let end_pc = self.cur().current_pc();
                self.cur_mut().patch_jump(skip_jmp, end_pc);
            }
            Expr::Binary { lhs, op, rhs } => {
                let l_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(lhs, l_reg)?;
                let r_reg = self.cur_mut().alloc_reg()?;
                self.compile_expr_into(rhs, r_reg)?;
                let instr = match op {
                    BinOp::Add => Instr::Add { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Sub => Instr::Sub { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Mul => Instr::Mul { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Div => Instr::Div { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::FloorDiv => Instr::Idiv { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Mod => Instr::Mod { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Pow => Instr::Pow { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Concat => Instr::Concat { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Eq => Instr::CmpEq { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Ne => Instr::CmpNe { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Lt => Instr::CmpLt { dst, lhs: l_reg, rhs: r_reg },
                    BinOp::Le => Instr::CmpLe { dst, lhs: l_reg, rhs: r_reg },
                    // Canonicalize `a > b` -> `b < a` and `a >= b` -> `b <= a`
                    // (Matches Lua/Luau `__lt` / `__le` metamethod rules!)
                    BinOp::Gt => Instr::CmpLt { dst, lhs: r_reg, rhs: l_reg },
                    BinOp::Ge => Instr::CmpLe { dst, lhs: r_reg, rhs: l_reg },
                    BinOp::And | BinOp::Or => unreachable!(),
                };
                self.cur_mut().emit(instr);
            }
            Expr::IfExpr {
                branches,
                else_expr,
            } => {
                let mut end_jumps = Vec::new();
                for (cond, val) in branches {
                    let c_reg = self.cur_mut().alloc_reg()?;
                    self.compile_expr_into(cond, c_reg)?;
                    let false_jmp = self.cur_mut().emit(Instr::JumpIfFalse {
                        cond: c_reg,
                        target: 0,
                    });
                    self.compile_expr_into(val, dst)?;
                    end_jumps.push(self.cur_mut().emit(Instr::Jump { target: 0 }));
                    let next_pc = self.cur().current_pc();
                    self.cur_mut().patch_jump(false_jmp, next_pc);
                }
                self.compile_expr_into(else_expr, dst)?;
                let end_pc = self.cur().current_pc();
                for ej in end_jumps {
                    self.cur_mut().patch_jump(ej, end_pc);
                }
            }
            Expr::InterpString { segments, exprs } => {
                // Build non-empty parts into temporary registers and fold with Concat
                let mut part_regs = Vec::new();
                for (i, expr_item) in exprs.iter().enumerate() {
                    if !segments[i].is_empty() {
                        let sr = self.cur_mut().alloc_reg()?;
                        let k = self.cur_mut().intern_string(&segments[i]);
                        self.cur_mut().emit(Instr::LoadK { dst: sr, k });
                        part_regs.push(sr);
                    }
                    let er = self.cur_mut().alloc_reg()?;
                    self.compile_expr_into(expr_item, er)?;
                    self.cur_mut().emit(Instr::ToString { dst: er, src: er });
                    part_regs.push(er);
                }
                if let Some(last_seg) = segments.last() {
                    if !last_seg.is_empty() {
                        let sr = self.cur_mut().alloc_reg()?;
                        let k = self.cur_mut().intern_string(last_seg);
                        self.cur_mut().emit(Instr::LoadK { dst: sr, k });
                        part_regs.push(sr);
                    }
                }
                if part_regs.is_empty() {
                    let k = self.cur_mut().intern_string(b"");
                    self.cur_mut().emit(Instr::LoadK { dst, k });
                } else if part_regs.len() == 1 {
                    if part_regs[0] != dst {
                        self.cur_mut().emit(Instr::Move {
                            dst,
                            src: part_regs[0],
                        });
                    }
                } else {
                    let mut acc = *part_regs.last().unwrap();
                    for &lhs in part_regs[..part_regs.len() - 1].iter().rev() {
                        self.cur_mut().emit(Instr::Concat {
                            dst: lhs,
                            lhs,
                            rhs: acc,
                        });
                        acc = lhs;
                    }
                    if acc != dst {
                        self.cur_mut().emit(Instr::Move { dst, src: acc });
                    }
                }
            }
            Expr::Table(fields) => {
                let tbl_reg = self.cur_mut().alloc_reg()?;
                let array_hint = fields
                    .iter()
                    .filter(|f| matches!(f, TableField::Array(_)))
                    .count()
                    .min(u16::MAX as usize) as u16;
                self.cur_mut().emit(Instr::NewTable {
                    dst: tbl_reg,
                    array_hint,
                });

                let mut array_offset: u32 = 0;
                let mut batch_exprs: Vec<&Expr> = Vec::new();
                let total_fields = fields.len();

                for (idx, field) in fields.iter().enumerate() {
                    let is_last = idx + 1 == total_fields;
                    match field {
                        TableField::Array(e) if is_last && is_multret_expr(e) => {
                            if !batch_exprs.is_empty() {
                                self.flush_table_batch(tbl_reg, &mut batch_exprs, &mut array_offset)?;
                            }
                            let mult_base = self.cur_mut().alloc_reg()?;
                            self.compile_multret_producer(e, mult_base)?;
                            self.cur_mut().emit(Instr::SetListMultret {
                                tbl: tbl_reg,
                                src_start: mult_base,
                                array_offset,
                            });
                        }
                        TableField::Array(e) => {
                            batch_exprs.push(e);
                            if batch_exprs.len() >= 32 {
                                self.flush_table_batch(tbl_reg, &mut batch_exprs, &mut array_offset)?;
                            }
                        }
                        TableField::Name { field: name, value } => {
                            if !batch_exprs.is_empty() {
                                self.flush_table_batch(tbl_reg, &mut batch_exprs, &mut array_offset)?;
                            }
                            let field_saved = self.cur().reg_top;
                            let val_reg = self.cur_mut().alloc_reg()?;
                            self.compile_expr_into(value, val_reg)?;
                            let key_k = self.cur_mut().intern_string(name.as_bytes());
                            self.cur_mut().emit(Instr::SetField {
                                tbl: tbl_reg,
                                key_k,
                                val: val_reg,
                            });
                            self.cur_mut().reg_top = field_saved;
                        }
                        TableField::Index { key, value } => {
                            if !batch_exprs.is_empty() {
                                self.flush_table_batch(tbl_reg, &mut batch_exprs, &mut array_offset)?;
                            }
                            let field_saved = self.cur().reg_top;
                            let key_reg = self.cur_mut().alloc_reg()?;
                            self.compile_expr_into(key, key_reg)?;
                            let val_reg = self.cur_mut().alloc_reg()?;
                            self.compile_expr_into(value, val_reg)?;
                            self.cur_mut().emit(Instr::SetTable {
                                tbl: tbl_reg,
                                key: key_reg,
                                val: val_reg,
                            });
                            self.cur_mut().reg_top = field_saved;
                        }
                    }
                }
                if !batch_exprs.is_empty() {
                    self.flush_table_batch(tbl_reg, &mut batch_exprs, &mut array_offset)?;
                }
                if tbl_reg != dst {
                    self.cur_mut().emit(Instr::Move { dst, src: tbl_reg });
                }
            }
        }

        self.cur_mut().reg_top = saved_top;
        Ok(())
    }

    fn flush_table_batch(
        &mut self,
        tbl_reg: Reg,
        batch: &mut Vec<&Expr>,
        array_offset: &mut u32,
    ) -> Result<(), LowerError> {
        let count = batch.len() as u16;
        let saved = self.cur().reg_top;
        let start = self.cur_mut().alloc_regs(count)?;
        for (i, e) in batch.drain(..).enumerate() {
            self.compile_expr_into(e, start + i as u16)?;
        }
        self.cur_mut().emit(Instr::SetList {
            tbl: tbl_reg,
            src_start: start,
            count,
            array_offset: *array_offset,
        });
        *array_offset += count as u32;
        self.cur_mut().reg_top = saved;
        Ok(())
    }
}

fn is_multret_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call { .. } | Expr::MethodCall { .. } | Expr::Vararg)
}
