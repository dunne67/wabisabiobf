use crate::ir::{ConstIdx, Constant, Instr, IrModule, Pc, Proto};

/// Lightweight SplitMix64 PRNG local to `wabisabi-ir` for deterministic IR obfuscation passes.
struct IrRng(u64);

impl IrRng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0xD1B5_4A32_D192_ED03)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % (bound as u64)) as usize
    }

    fn range_i32(&mut self, lo: i32, hi: i32) -> i32 {
        let span = (hi - lo + 1) as u64;
        lo + (self.next_u64() % span) as i32
    }

    fn shuffle<T>(&mut self, slice: &mut [T]) {
        for i in (1..slice.len()).rev() {
            let j = self.next_usize(i + 1);
            slice.swap(i, j);
        }
    }
}

/// Applies Phase 3 IR hardening passes selectively to cold paths (`loop_depth == 0`)
/// so inner-loop execution speed stays untouched while entry/init/auth logic gets
/// algebraic constant splitting, opaque-predicate diamond/bogus CFG edges, and
/// shuffled + decoy-padded constant pools.
pub fn obfuscate_ir(module: &mut IrModule, seed: u64) {
    let mut rng = IrRng::new(seed);
    for (p_idx, proto) in module.protos.iter_mut().enumerate() {
        let sub_seed = rng.next_u64() ^ (p_idx as u64).wrapping_mul(0x94D0_49BB_1331_11EB);
        let mut prng = IrRng::new(sub_seed);
        harden_proto(proto, &mut prng);
    }
}

fn harden_proto(proto: &mut Proto, rng: &mut IrRng) {
    if proto.code.is_empty() {
        return;
    }

    // 1. Split cold integer constants into 2-step algebraic reconstructions + inject cold opaque predicates
    transform_cold_instructions(proto, rng);

    // 2. Scrub any constants that became unreferenced after constant splitting (removes original plain numbers!)
    remove_dead_constants(proto);

    // 3. Inject plausible decoy constants and shuffle the entire constant pool
    shuffle_and_pad_constants(proto, rng);
}

fn compute_cold_mask(code: &[Instr]) -> Vec<bool> {
    let n = code.len();
    let mut in_loop = vec![false; n];
    for (pc, ins) in code.iter().enumerate() {
        let back = match *ins {
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
        if let Some(t) = back {
            for slot in &mut in_loop[t..=pc] {
                *slot = true;
            }
        }
    }
    in_loop.into_iter().map(|l| !l).collect()
}

fn is_multret_producer_instr(ins: &Instr) -> bool {
    matches!(
        ins,
        Instr::Call {
            ret_count: None,
            ..
        } | Instr::CallMultret {
            ret_count: None,
            ..
        } | Instr::Vararg { count: None, .. }
    )
}

fn find_or_add_const(constants: &mut Vec<Constant>, c: Constant) -> ConstIdx {
    for (i, existing) in constants.iter().enumerate() {
        let eq = match (existing, &c) {
            (Constant::Nil, Constant::Nil) => true,
            (Constant::Bool(a), Constant::Bool(b)) => a == b,
            (Constant::Number(a), Constant::Number(b)) => a.to_bits() == b.to_bits(),
            (Constant::String(a), Constant::String(b)) => a == b,
            _ => false,
        };
        if eq {
            return i as ConstIdx;
        }
    }
    let idx = constants.len() as ConstIdx;
    constants.push(c);
    idx
}

fn transform_cold_instructions(proto: &mut Proto, rng: &mut IrRng) {
    if proto.max_regs > 65000 {
        return;
    }
    let cold = compute_cold_mask(&proto.code);
    let s1 = proto.max_regs;
    let s2 = proto.max_regs + 1;
    let mut used_scratch = false;

    let old_len = proto.code.len();
    let mut old_to_new: Vec<Pc> = vec![0; old_len + 1];
    let mut new_code: Vec<Instr> = Vec::with_capacity(old_len + 16);

    // Reserve a placeholder list of `(jmp_instr_idx_in_new_code)` that will jump to bogus trap blocks appended at end
    let mut trap_jumps: Vec<usize> = Vec::new();
    let mut injected_opaques = 0usize;

    for (old_pc, ins) in proto.code.clone().into_iter().enumerate() {
        old_to_new[old_pc] = new_code.len() as Pc;

        let prev_is_multret = old_pc > 0 && is_multret_producer_instr(&proto.code[old_pc - 1]);
        let is_cold = cold[old_pc] && !prev_is_multret;

        // Occasional cold-path algebraic opaque predicate before safe statements/loads
        if is_cold
            && injected_opaques < 4
            && !matches!(
                ins,
                Instr::Return { .. }
                    | Instr::ReturnMultret { .. }
                    | Instr::ForNumPrep { .. }
                    | Instr::ForNumLoop { .. }
                    | Instr::IterLoop { .. }
            )
            && rng.next_usize(5) == 0
        {
            used_scratch = true;
            injected_opaques += 1;
            let base_val = rng.range_i32(13, 499) as f64;
            let k_base = find_or_add_const(&mut proto.constants, Constant::Number(base_val));
            let k_dbl = find_or_add_const(&mut proto.constants, Constant::Number(base_val * 2.0));

            // Invariant: `(base_val + base_val) == (base_val * 2)` -> always true!
            new_code.push(Instr::LoadK {
                dst: s1,
                k: k_base,
            });
            new_code.push(Instr::Add {
                dst: s2,
                lhs: s1,
                rhs: s1,
            });
            new_code.push(Instr::LoadK { dst: s1, k: k_dbl });
            new_code.push(Instr::CmpEq {
                dst: s1,
                lhs: s2,
                rhs: s1,
            });
            let jmp_idx = new_code.len();
            new_code.push(Instr::JumpIfFalse {
                cond: s1,
                target: 0,
            });
            trap_jumps.push(jmp_idx);
        }

        // Cold constant load & jump lowering:
        // 1) Algebraic integer constant splitting (`LoadK + LoadK + Add/Sub`)
        // 2) Stateful persistent scratch pair (`KPrep + Commit`)
        // 3) Self-modifying first-execution rewrites (`LoadKInit`, `JumpInit`)
        if is_cold {
            match ins {
                Instr::LoadK { dst, k } => {
                    if let Constant::Number(n) = proto.constants[k as usize] {
                        let is_pos_or_neg_int = n.is_finite()
                            && n.fract() == 0.0
                            && n.abs() <= 1_000_000.0
                            && !(n == 0.0 && n.is_sign_negative());
                        if is_pos_or_neg_int && rng.next_usize(3) != 0 {
                            used_scratch = true;
                            let mut delta = rng.range_i32(-40_000, 40_000);
                            if delta == 0 {
                                delta = 1337;
                            }
                            let df = delta as f64;
                            if rng.next_usize(2) == 0 {
                                let k_a = find_or_add_const(
                                    &mut proto.constants,
                                    Constant::Number(n + df),
                                );
                                let k_b =
                                    find_or_add_const(&mut proto.constants, Constant::Number(df));
                                new_code.push(Instr::LoadKInit { dst, k: k_a });
                                new_code.push(Instr::LoadK { dst: s1, k: k_b });
                                new_code.push(Instr::Sub {
                                    dst,
                                    lhs: dst,
                                    rhs: s1,
                                });
                            } else {
                                let k_a = find_or_add_const(
                                    &mut proto.constants,
                                    Constant::Number(n - df),
                                );
                                let k_b =
                                    find_or_add_const(&mut proto.constants, Constant::Number(df));
                                new_code.push(Instr::KPrep { dst, k: k_a });
                                new_code.push(Instr::Commit);
                                new_code.push(Instr::LoadK { dst: s1, k: k_b });
                                new_code.push(Instr::Add {
                                    dst,
                                    lhs: dst,
                                    rhs: s1,
                                });
                            }
                            continue;
                        }
                    }
                    match rng.next_usize(3) {
                        0 => {
                            new_code.push(Instr::KPrep { dst, k });
                            new_code.push(Instr::Commit);
                            continue;
                        }
                        1 => {
                            new_code.push(Instr::LoadKInit { dst, k });
                            continue;
                        }
                        _ => {}
                    }
                }
                Instr::Jump { target } if rng.next_usize(2) == 0 => {
                    new_code.push(Instr::JumpInit { target });
                    continue;
                }
                _ => {}
            }
        }

        new_code.push(ins);
    }

    old_to_new[old_len] = new_code.len() as Pc;

    // Remap all original jump targets through `old_to_new`
    for ins in &mut new_code {
        match ins {
            Instr::Jump { target }
            | Instr::JumpInit { target }
            | Instr::JumpIfTrue { target, .. }
            | Instr::JumpIfFalse { target, .. } => {
                if (*target as usize) < old_to_new.len() {
                    *target = old_to_new[*target as usize];
                }
            }
            Instr::ForNumPrep { exit_pc, .. } | Instr::IterLoop { exit_pc, .. } => {
                if (*exit_pc as usize) < old_to_new.len() {
                    *exit_pc = old_to_new[*exit_pc as usize];
                }
            }
            Instr::ForNumLoop { body_pc, .. } => {
                if (*body_pc as usize) < old_to_new.len() {
                    *body_pc = old_to_new[*body_pc as usize];
                }
            }
            _ => {}
        }
    }

    // Append unreachable bogus CFG trap blocks at the end (after trailing Return) and wire `trap_jumps`
    if !trap_jumps.is_empty() {
        let trap_pc = new_code.len() as Pc;
        let decoy_k = find_or_add_const(
            &mut proto.constants,
            Constant::Number(rng.range_i32(1, 999) as f64),
        );
        new_code.push(Instr::LoadK {
            dst: s1,
            k: decoy_k,
        });
        new_code.push(Instr::Add {
            dst: s2,
            lhs: s1,
            rhs: s1,
        });
        // Self-looping or returning bogus tail confuses static CFG builders
        new_code.push(Instr::Return {
            start: s2,
            count: 1,
        });

        for j_idx in trap_jumps {
            if let Instr::JumpIfFalse { target, .. } = &mut new_code[j_idx] {
                *target = trap_pc;
            }
        }
    }

    if used_scratch {
        proto.max_regs = proto.max_regs.saturating_add(2);
    }
    proto.code = new_code;
}

fn remove_dead_constants(proto: &mut Proto) {
    let mut used = vec![false; proto.constants.len()];
    for ins in &proto.code {
        match *ins {
            Instr::LoadK { k, .. }
            | Instr::LoadKInit { k, .. }
            | Instr::KPrep { k, .. }
            | Instr::GetGlobal { name_k: k, .. }
            | Instr::SetGlobal { name_k: k, .. }
            | Instr::GetField { key_k: k, .. }
            | Instr::SetField { key_k: k, .. }
            | Instr::SelfMethod { method_k: k, .. } => {
                if (k as usize) < used.len() {
                    used[k as usize] = true;
                }
            }
            _ => {}
        }
    }

    let mut remap = vec![0 as ConstIdx; proto.constants.len()];
    let mut compact = Vec::with_capacity(proto.constants.len());
    for (old_i, c) in proto.constants.drain(..).enumerate() {
        if used[old_i] {
            remap[old_i] = compact.len() as ConstIdx;
            compact.push(c);
        }
    }
    proto.constants = compact;
    remap_proto_const_indices(proto, &remap);
}

fn shuffle_and_pad_constants(proto: &mut Proto, rng: &mut IrRng) {
    const DECOY_WORDS: &[&[u8]] = &[
        b"__index",
        b"__newindex",
        b"__metatable",
        b"value",
        b"state",
        b"init",
        b" step",
        b"handler",
    ];
    let pad_count = 1 + rng.next_usize(3);
    for _ in 0..pad_count {
        if rng.next_usize(2) == 0 {
            let w = DECOY_WORDS[rng.next_usize(DECOY_WORDS.len())];
            proto.constants.push(Constant::String(w.to_vec()));
        } else {
            proto
                .constants
                .push(Constant::Number(rng.range_i32(-9999, 9999) as f64));
        }
    }

    let n = proto.constants.len();
    if n <= 1 {
        return;
    }
    let mut order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut order);

    let mut old_to_new = vec![0 as ConstIdx; n];
    let mut shuffled = Vec::with_capacity(n);
    for (new_idx, &old_idx) in order.iter().enumerate() {
        old_to_new[old_idx] = new_idx as ConstIdx;
        shuffled.push(proto.constants[old_idx].clone());
    }
    proto.constants = shuffled;
    remap_proto_const_indices(proto, &old_to_new);
}

fn remap_proto_const_indices(proto: &mut Proto, map: &[ConstIdx]) {
    for ins in &mut proto.code {
        match ins {
            Instr::LoadK { k, .. }
            | Instr::LoadKInit { k, .. }
            | Instr::KPrep { k, .. }
            | Instr::GetGlobal { name_k: k, .. }
            | Instr::SetGlobal { name_k: k, .. }
            | Instr::GetField { key_k: k, .. }
            | Instr::SetField { key_k: k, .. }
            | Instr::SelfMethod { method_k: k, .. } => {
                *k = map[*k as usize];
            }
            _ => {}
        }
    }
}
