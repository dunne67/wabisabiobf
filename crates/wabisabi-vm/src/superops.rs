use std::collections::HashMap;
use wabisabi_ir::ir::{Instr, IrModule, Proto};

pub const MAX_SUPEROPS: usize = 36;
pub const MAX_SUPEROP_LEN: usize = 5;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BaseOp {
    LoadNil = 0,
    LoadBool = 1,
    LoadK = 2,
    Move = 3,
    GetGlobal = 4,
    SetGlobal = 5,
    GetUpval = 6,
    SetUpval = 7,
    CloseUpvals = 8,
    Closure = 9,
    NewTable = 10,
    GetTable = 11,
    GetField = 12,
    SetTable = 13,
    SetField = 14,
    SetList = 15,
    SetListMultret = 16,
    SelfMethod = 17,
    Add = 18,
    Sub = 19,
    Mul = 20,
    Div = 21,
    Idiv = 22,
    Mod = 23,
    Pow = 24,
    Concat = 25,
    ToString = 26,
    Neg = 27,
    Not = 28,
    Len = 29,
    CmpEq = 30,
    CmpNe = 31,
    CmpLt = 32,
    CmpLe = 33,
    Jump = 34,
    JumpIfTrue = 35,
    JumpIfFalse = 36,
    Call = 37,
    CallMultret = 38,
    Vararg = 39,
    Return = 40,
    ReturnMultret = 41,
    ForNumPrep = 42,
    ForNumLoop = 43,
    IterPrep = 44,
    IterLoop = 45,
    LoadKInit = 46,
    JumpInit = 47,
    KPrep = 48,
    Commit = 49,
}

impl BaseOp {
    pub const COUNT: usize = 50;

    pub const ALL: [BaseOp; Self::COUNT] = [
        BaseOp::LoadNil,
        BaseOp::LoadBool,
        BaseOp::LoadK,
        BaseOp::Move,
        BaseOp::GetGlobal,
        BaseOp::SetGlobal,
        BaseOp::GetUpval,
        BaseOp::SetUpval,
        BaseOp::CloseUpvals,
        BaseOp::Closure,
        BaseOp::NewTable,
        BaseOp::GetTable,
        BaseOp::GetField,
        BaseOp::SetTable,
        BaseOp::SetField,
        BaseOp::SetList,
        BaseOp::SetListMultret,
        BaseOp::SelfMethod,
        BaseOp::Add,
        BaseOp::Sub,
        BaseOp::Mul,
        BaseOp::Div,
        BaseOp::Idiv,
        BaseOp::Mod,
        BaseOp::Pow,
        BaseOp::Concat,
        BaseOp::ToString,
        BaseOp::Neg,
        BaseOp::Not,
        BaseOp::Len,
        BaseOp::CmpEq,
        BaseOp::CmpNe,
        BaseOp::CmpLt,
        BaseOp::CmpLe,
        BaseOp::Jump,
        BaseOp::JumpIfTrue,
        BaseOp::JumpIfFalse,
        BaseOp::Call,
        BaseOp::CallMultret,
        BaseOp::Vararg,
        BaseOp::Return,
        BaseOp::ReturnMultret,
        BaseOp::ForNumPrep,
        BaseOp::ForNumLoop,
        BaseOp::IterPrep,
        BaseOp::IterLoop,
        BaseOp::LoadKInit,
        BaseOp::JumpInit,
        BaseOp::KPrep,
        BaseOp::Commit,
    ];

    pub fn from_instr(ins: &Instr) -> Self {
        match ins {
            Instr::LoadNil { .. } => BaseOp::LoadNil,
            Instr::LoadBool { .. } => BaseOp::LoadBool,
            Instr::LoadK { .. } => BaseOp::LoadK,
            Instr::Move { .. } => BaseOp::Move,
            Instr::GetGlobal { .. } => BaseOp::GetGlobal,
            Instr::SetGlobal { .. } => BaseOp::SetGlobal,
            Instr::GetUpval { .. } => BaseOp::GetUpval,
            Instr::SetUpval { .. } => BaseOp::SetUpval,
            Instr::CloseUpvals { .. } => BaseOp::CloseUpvals,
            Instr::Closure { .. } => BaseOp::Closure,
            Instr::NewTable { .. } => BaseOp::NewTable,
            Instr::GetTable { .. } => BaseOp::GetTable,
            Instr::GetField { .. } => BaseOp::GetField,
            Instr::SetTable { .. } => BaseOp::SetTable,
            Instr::SetField { .. } => BaseOp::SetField,
            Instr::SetList { .. } => BaseOp::SetList,
            Instr::SetListMultret { .. } => BaseOp::SetListMultret,
            Instr::SelfMethod { .. } => BaseOp::SelfMethod,
            Instr::Add { .. } => BaseOp::Add,
            Instr::Sub { .. } => BaseOp::Sub,
            Instr::Mul { .. } => BaseOp::Mul,
            Instr::Div { .. } => BaseOp::Div,
            Instr::Idiv { .. } => BaseOp::Idiv,
            Instr::Mod { .. } => BaseOp::Mod,
            Instr::Pow { .. } => BaseOp::Pow,
            Instr::Concat { .. } => BaseOp::Concat,
            Instr::ToString { .. } => BaseOp::ToString,
            Instr::Neg { .. } => BaseOp::Neg,
            Instr::Not { .. } => BaseOp::Not,
            Instr::Len { .. } => BaseOp::Len,
            Instr::CmpEq { .. } => BaseOp::CmpEq,
            Instr::CmpNe { .. } => BaseOp::CmpNe,
            Instr::CmpLt { .. } => BaseOp::CmpLt,
            Instr::CmpLe { .. } => BaseOp::CmpLe,
            Instr::Jump { .. } => BaseOp::Jump,
            Instr::JumpIfTrue { .. } => BaseOp::JumpIfTrue,
            Instr::JumpIfFalse { .. } => BaseOp::JumpIfFalse,
            Instr::Call { .. } => BaseOp::Call,
            Instr::CallMultret { .. } => BaseOp::CallMultret,
            Instr::Vararg { .. } => BaseOp::Vararg,
            Instr::Return { .. } => BaseOp::Return,
            Instr::ReturnMultret { .. } => BaseOp::ReturnMultret,
            Instr::ForNumPrep { .. } => BaseOp::ForNumPrep,
            Instr::ForNumLoop { .. } => BaseOp::ForNumLoop,
            Instr::IterPrep { .. } => BaseOp::IterPrep,
            Instr::IterLoop { .. } => BaseOp::IterLoop,
            Instr::LoadKInit { .. } => BaseOp::LoadKInit,
            Instr::JumpInit { .. } => BaseOp::JumpInit,
            Instr::KPrep { .. } => BaseOp::KPrep,
            Instr::Commit => BaseOp::Commit,
        }
    }

    pub fn is_control_flow(self) -> bool {
        matches!(
            self,
            BaseOp::Jump
                | BaseOp::JumpInit
                | BaseOp::JumpIfTrue
                | BaseOp::JumpIfFalse
                | BaseOp::Return
                | BaseOp::ReturnMultret
                | BaseOp::ForNumPrep
                | BaseOp::ForNumLoop
                | BaseOp::IterLoop
        )
    }

    pub fn is_excluded_from_fusion(self) -> bool {
        matches!(
            self,
            BaseOp::Closure
                | BaseOp::ForNumPrep
                | BaseOp::LoadKInit
                | BaseOp::JumpInit
                | BaseOp::KPrep
                | BaseOp::Commit
        )
    }

    pub fn is_heavy_handler(self) -> bool {
        matches!(
            self,
            BaseOp::Call | BaseOp::CallMultret | BaseOp::IterLoop | BaseOp::Vararg | BaseOp::Return
        )
    }
}

#[derive(Debug, Clone)]
pub struct SuperOpDef {
    pub id: usize,
    pub pattern: Vec<BaseOp>,
}

#[derive(Debug, Clone)]
pub enum FusedSlot {
    /// Standalone base instruction.
    Base { ins: Instr, weight: u64 },
    /// Head of a fused `K`-instruction superoperator (`K = steps.len()`).
    SuperHead {
        super_id: usize,
        steps: Vec<Instr>,
        weight: u64,
    },
    /// Interior slot (`1 .. K-1`) of a preceding `SuperHead`:
    /// carries the real operands for `steps[step_offset]` while its `OP` byte is chaff!
    SuperTail {
        super_id: usize,
        step_offset: usize,
        ins: Instr,
    },
}

#[derive(Debug, Clone)]
pub struct FusedProto {
    pub slots: Vec<FusedSlot>,
}

#[derive(Debug, Clone)]
pub struct FusedModule {
    pub superops: Vec<SuperOpDef>,
    pub protos: Vec<FusedProto>,
}

pub fn build_fused_module(module: &IrModule) -> FusedModule {
    let mut proto_blocks: Vec<Vec<(usize, usize)>> = Vec::with_capacity(module.protos.len());
    let mut proto_weights: Vec<Vec<u64>> = Vec::with_capacity(module.protos.len());

    for proto in &module.protos {
        let blocks = compute_basic_blocks(proto);
        let weights = compute_loop_weights(proto);
        proto_blocks.push(blocks);
        proto_weights.push(weights);
    }

    // Score candidate straight-line sequences inside basic blocks
    let mut pattern_scores: HashMap<Vec<BaseOp>, u64> = HashMap::new();

    for (p_idx, proto) in module.protos.iter().enumerate() {
        let ops: Vec<BaseOp> = proto.code.iter().map(BaseOp::from_instr).collect();
        let weights = &proto_weights[p_idx];

        for &(b_start, b_end) in &proto_blocks[p_idx] {
            let b_len = b_end - b_start;
            if b_len < 2 {
                continue;
            }
            let max_win = b_len.min(MAX_SUPEROP_LEN);
            for win_len in 2..=max_win {
                let mut i = b_start;
                while i + win_len <= b_end {
                    let slice = &ops[i..i + win_len];
                    if is_valid_superop_slice(slice) {
                        let w = weights[i];
                        // Bonus if window covers the entire basic block (e.g., whole inner loop!)
                        let full_block_bonus = if win_len == b_len { 2 } else { 1 };
                        let saved = ((win_len - 1) as u64)
                            .saturating_mul(w)
                            .saturating_mul(full_block_bonus);
                        let entry = pattern_scores.entry(slice.to_vec()).or_insert(0);
                        *entry = entry.saturating_add(saved);
                        // Advance non-overlapping for realistic frequency scoring
                        i += win_len;
                    } else {
                        i += 1;
                    }
                }
            }
        }
    }

    // Rank candidates by score descending (tie-break deterministically by pattern)
    let mut ranked: Vec<(Vec<BaseOp>, u64)> = pattern_scores
        .into_iter()
        .filter(|(_, score)| *score >= 2)
        .collect();
    ranked.sort_by(|(pa, sa), (pb, sb)| sb.cmp(sa).then_with(|| pb.len().cmp(&pa.len())).then_with(|| pa.cmp(pb)));

    let chosen_patterns: Vec<Vec<BaseOp>> = ranked
        .into_iter()
        .take(MAX_SUPEROPS)
        .map(|(pat, _)| pat)
        .collect();

    let mut pat_lookup: HashMap<Vec<BaseOp>, usize> = HashMap::new();
    let mut superops = Vec::with_capacity(chosen_patterns.len());
    for (id, pat) in chosen_patterns.into_iter().enumerate() {
        pat_lookup.insert(pat.clone(), id);
        superops.push(SuperOpDef { id, pattern: pat });
    }

    // Apply greedy longest-match fusion within each basic block, tracking actual used superops
    let mut used_superops = vec![false; superops.len()];
    let mut fused_protos = Vec::with_capacity(module.protos.len());

    for (p_idx, proto) in module.protos.iter().enumerate() {
        let ops: Vec<BaseOp> = proto.code.iter().map(BaseOp::from_instr).collect();
        let weights = &proto_weights[p_idx];
        let mut slots: Vec<Option<FusedSlot>> = vec![None; proto.code.len()];

        for &(b_start, b_end) in &proto_blocks[p_idx] {
            let mut pc = b_start;
            while pc < b_end {
                let max_try = (b_end - pc).min(MAX_SUPEROP_LEN);
                let mut matched: Option<(usize, usize)> = None;
                for len in (2..=max_try).rev() {
                    if let Some(&sid) = pat_lookup.get(&ops[pc..pc + len]) {
                        matched = Some((sid, len));
                        break;
                    }
                }
                if let Some((sid, len)) = matched {
                    used_superops[sid] = true;
                    let steps: Vec<Instr> = proto.code[pc..pc + len].to_vec();
                    slots[pc] = Some(FusedSlot::SuperHead {
                        super_id: sid,
                        steps: steps.clone(),
                        weight: weights[pc],
                    });
                    for off in 1..len {
                        slots[pc + off] = Some(FusedSlot::SuperTail {
                            super_id: sid,
                            step_offset: off,
                            ins: steps[off].clone(),
                        });
                    }
                    pc += len;
                } else {
                    slots[pc] = Some(FusedSlot::Base {
                        ins: proto.code[pc].clone(),
                        weight: weights[pc],
                    });
                    pc += 1;
                }
            }
        }

        let finalized: Vec<FusedSlot> = slots
            .into_iter()
            .enumerate()
            .map(|(idx, s)| {
                s.unwrap_or_else(|| FusedSlot::Base {
                    ins: proto.code[idx].clone(),
                    weight: 1,
                })
            })
            .collect();
        fused_protos.push(FusedProto { slots: finalized });
    }

    // Compact superop IDs to remove any candidate completely shadowed by longer superops
    let mut remap = vec![None; superops.len()];
    let mut compact_superops = Vec::new();
    for (old_id, def) in superops.into_iter().enumerate() {
        if used_superops[old_id] {
            let new_id = compact_superops.len();
            remap[old_id] = Some(new_id);
            compact_superops.push(SuperOpDef {
                id: new_id,
                pattern: def.pattern,
            });
        }
    }

    for fp in &mut fused_protos {
        for slot in &mut fp.slots {
            match slot {
                FusedSlot::SuperHead { super_id, .. } | FusedSlot::SuperTail { super_id, .. } => {
                    *super_id = remap[*super_id].expect("used superop must have remapped id");
                }
                FusedSlot::Base { .. } => {}
            }
        }
    }

    FusedModule {
        superops: compact_superops,
        protos: fused_protos,
    }
}

/// Synthesizes a unified superoperator table across BOTH the Outer Protection Module
/// and the Inner User Module so a single polymorphic VM runs both stages seamlessly.
pub fn build_fused_pair(outer: &IrModule, inner: &IrModule) -> (FusedModule, FusedModule) {
    let split = outer.protos.len();
    let mut combined_protos = Vec::with_capacity(split + inner.protos.len());
    combined_protos.extend_from_slice(&outer.protos);
    combined_protos.extend_from_slice(&inner.protos);

    let combined_ir = IrModule {
        protos: combined_protos,
        main_proto: 0,
    };
    let mut combined_fused = build_fused_module(&combined_ir);
    let inner_protos = combined_fused.protos.split_off(split);
    let outer_protos = combined_fused.protos;
    let shared_superops = combined_fused.superops;

    (
        FusedModule {
            superops: shared_superops.clone(),
            protos: outer_protos,
        },
        FusedModule {
            superops: shared_superops,
            protos: inner_protos,
        },
    )
}

fn is_valid_superop_slice(slice: &[BaseOp]) -> bool {
    if slice.len() < 2 {
        return false;
    }
    let mut heavy_count = 0usize;
    for (idx, &op) in slice.iter().enumerate() {
        if op.is_excluded_from_fusion() {
            return false;
        }
        // Only the final instruction in a superoperator may alter `pc` or `return`
        if idx + 1 < slice.len() && op.is_control_flow() {
            return false;
        }
        if op.is_heavy_handler() {
            heavy_count += 1;
            if heavy_count > 1 {
                return false;
            }
        }
    }
    true
}

fn compute_basic_blocks(proto: &Proto) -> Vec<(usize, usize)> {
    let n = proto.code.len();
    if n == 0 {
        return Vec::new();
    }
    let mut leaders = vec![false; n + 1];
    leaders[0] = true;
    leaders[n] = true;

    let mark = |leaders: &mut [bool], target: u32| {
        let t = target as usize;
        if t <= n {
            leaders[t] = true;
        }
    };

    for (pc, ins) in proto.code.iter().enumerate() {
        match *ins {
            Instr::Jump { target } | Instr::JumpInit { target } => {
                mark(&mut leaders, target);
                leaders[pc + 1] = true;
            }
            Instr::JumpIfTrue { target, .. } | Instr::JumpIfFalse { target, .. } => {
                mark(&mut leaders, target);
                leaders[pc + 1] = true;
            }
            Instr::ForNumPrep { exit_pc, .. } | Instr::IterLoop { exit_pc, .. } => {
                mark(&mut leaders, exit_pc);
                leaders[pc + 1] = true;
            }
            Instr::ForNumLoop { body_pc, .. } => {
                mark(&mut leaders, body_pc);
                leaders[pc + 1] = true;
            }
            Instr::Return { .. } | Instr::ReturnMultret { .. } => {
                leaders[pc + 1] = true;
            }
            _ => {}
        }
    }

    let mut blocks = Vec::new();
    let mut start = 0usize;
    for i in 1..=n {
        if leaders[i] {
            if i > start {
                blocks.push((start, i));
            }
            start = i;
        }
    }
    blocks
}

fn compute_loop_weights(proto: &Proto) -> Vec<u64> {
    let n = proto.code.len();
    let mut loop_depth = vec![0u32; n];

    for (pc, ins) in proto.code.iter().enumerate() {
        let back_target = match *ins {
            Instr::Jump { target }
            | Instr::JumpInit { target }
            | Instr::JumpIfTrue { target, .. }
            | Instr::JumpIfFalse { target, .. }
            | Instr::ForNumLoop { body_pc: target, .. } => {
                let t = target as usize;
                if t <= pc {
                    Some(t)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(t) = back_target {
            for d in &mut loop_depth[t..=pc] {
                *d = (*d + 1).min(4);
            }
        }
    }

    loop_depth
        .into_iter()
        .map(|d| 16u64.pow(d))
        .collect()
}
