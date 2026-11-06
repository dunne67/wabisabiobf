use crate::prng::Prng;
use crate::superops::{BaseOp, FusedModule, FusedSlot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoSection {
    Consts,
    Upvals,
    Code,
}

#[derive(Debug, Clone)]
pub enum VirtualOpKind {
    Base {
        op: BaseOp,
        /// Maps logical operand index `0..4` (`a, b, c, d`) -> physical array column `0..4` (`S0..S3`).
        perm: [usize; 4],
    },
    Super {
        super_id: usize,
        pattern: Vec<BaseOp>,
        /// Independent random operand column permutation for each step of this superoperator.
        step_perms: Vec<[usize; 4]>,
    },
    Decoy {
        variant: u8,
        perm: [usize; 4],
    },
}

#[derive(Debug, Clone)]
pub struct VirtualOp {
    pub code: u8,
    pub weight: u64,
    pub kind: VirtualOpKind,
}

/// Indices into `proto_slots: [usize; 12]` (values are shuffled 1-based Lua array slots `1..=12`).
pub mod proto_field {
    pub const NP: usize = 0;
    pub const VA: usize = 1;
    pub const MR: usize = 2;
    pub const K: usize = 3;
    pub const NUV: usize = 4;
    pub const UVM: usize = 5;
    pub const UVI: usize = 6;
    pub const OP: usize = 7;
    pub const S0: usize = 8;
    pub const S1: usize = 9;
    pub const S2: usize = 10;
    pub const S3: usize = 11;
}

#[derive(Debug, Clone, Copy)]
pub struct StreamCipherSpec {
    pub s1_init: u8,
    pub s2_init: u8,
    pub m1: u8,
    pub a1: u8,
    pub m2: u8,
    pub a2: u8,
}

#[derive(Debug, Clone)]
pub struct PolymorphicIsa {
    pub ops: Vec<VirtualOp>,
    pub base_variants: Vec<Vec<(u8, [usize; 4])>>,
    pub super_encodings: Vec<(u8, Vec<[usize; 4]>)>,
    pub chaff_opcodes: Vec<u8>,
    pub proto_sections: [ProtoSection; 3],
    /// Shuffled 1-based array indices `1..=12` for prototype table layout (zero named fields!).
    pub proto_slots: [usize; 12],
    /// Wire constant tags for eager outer chunk: `[nil, false, true, num, str]`.
    pub const_tags: [u8; 5],
    /// Wire constant tags for lazy inner materializer: `[nil, bool, num, str]`.
    pub lazy_tags: [u8; 4],
    pub upval_tags: (u8, u8),
    pub cipher: StreamCipherSpec,
    /// Additive delta masking replacement opcodes in self-modifying `LoadKInit` / `JumpInit`.
    pub selfmod_delta: u8,
    /// Positive bias added to jump targets in `JumpInit` before first-execution rewrite.
    pub jinit_bias: u32,
}

impl PolymorphicIsa {
    pub fn generate(fused: &FusedModule, rng: &mut Prng) -> Self {
        Self::generate_multi(&[fused], rng)
    }

    pub fn generate_multi(modules: &[&FusedModule], rng: &mut Prng) -> Self {
        let superop_len = modules.first().map(|m| m.superops.len()).unwrap_or(0);
        let mut base_weights = [0u64; BaseOp::COUNT];
        let mut base_counts = [0usize; BaseOp::COUNT];
        let mut super_weights = vec![0u64; superop_len];

        for fused in modules {
            for proto in &fused.protos {
                for slot in &proto.slots {
                    match slot {
                        FusedSlot::Base { ins, weight } => {
                            let bop = BaseOp::from_instr(ins) as usize;
                            base_counts[bop] += 1;
                            base_weights[bop] = base_weights[bop].saturating_add(*weight);
                        }
                        FusedSlot::SuperHead {
                            super_id, weight, ..
                        } => {
                            super_weights[*super_id] =
                                super_weights[*super_id].saturating_add(*weight);
                        }
                        FusedSlot::SuperTail { .. } => {}
                    }
                }
            }
        }

        // Self-modifying `LoadKInit` / `JumpInit` rewrite `OP[pc]` into `LoadK` / `Jump` at runtime,
        // so ensure the target base opcodes exist whenever their initializer forms exist!
        if base_counts[BaseOp::LoadKInit as usize] > 0 && base_counts[BaseOp::LoadK as usize] == 0 {
            base_counts[BaseOp::LoadK as usize] = 1;
            base_weights[BaseOp::LoadK as usize] = 1;
        }
        if base_counts[BaseOp::JumpInit as usize] > 0 && base_counts[BaseOp::Jump as usize] == 0 {
            base_counts[BaseOp::Jump as usize] = 1;
            base_weights[BaseOp::Jump as usize] = 1;
        }

        let mut used_bases: Vec<usize> = (0..BaseOp::COUNT)
            .filter(|&b| base_counts[b] > 0)
            .collect();
        used_bases.sort_by(|&a, &b| base_weights[b].cmp(&base_weights[a]));
        let mut alias_set = [false; BaseOp::COUNT];
        for &b in used_bases.iter().take(4) {
            let bop = BaseOp::ALL[b];
            if base_counts[b] >= 2
                && !bop.is_heavy_handler()
                && !matches!(
                    bop,
                    BaseOp::Closure
                        | BaseOp::LoadKInit
                        | BaseOp::JumpInit
                        | BaseOp::KPrep
                        | BaseOp::Commit
                )
            {
                alias_set[b] = true;
            }
        }

        let decoy_count = 3 + rng.next_usize(3);
        let total_vops = used_bases.len()
            + alias_set.iter().filter(|&&x| x).count()
            + superop_len
            + decoy_count;
        assert!(total_vops <= 250, "virtual opcode count exceeded u8 space");

        let mut pool: Vec<u8> = (1u8..=254u8).collect();
        rng.shuffle(&mut pool);
        let mut code_iter = pool.into_iter();

        let mut vops: Vec<VirtualOp> = Vec::with_capacity(total_vops);
        let mut base_variants: Vec<Vec<(u8, [usize; 4])>> = vec![Vec::new(); BaseOp::COUNT];

        // First allocate all non-initializer base ops (`0..46` + `KPrep` + `Commit`),
        // then allocate `LoadKInit` & `JumpInit` sharing `LoadK` / `Jump` column permutations!
        for b_idx in 0..BaseOp::COUNT {
            if base_counts[b_idx] == 0 {
                continue;
            }
            let bop = BaseOp::ALL[b_idx];
            if matches!(bop, BaseOp::LoadKInit | BaseOp::JumpInit) {
                continue;
            }
            if alias_set[b_idx] {
                let w_half = (base_weights[b_idx] / 2).max(1);
                for _ in 0..2 {
                    let code = code_iter.next().unwrap();
                    let perm = rand_perm4(rng);
                    base_variants[b_idx].push((code, perm));
                    vops.push(VirtualOp {
                        code,
                        weight: w_half,
                        kind: VirtualOpKind::Base { op: bop, perm },
                    });
                }
            } else {
                let code = code_iter.next().unwrap();
                let perm = rand_perm4(rng);
                base_variants[b_idx].push((code, perm));
                vops.push(VirtualOp {
                    code,
                    weight: base_weights[b_idx].max(1),
                    kind: VirtualOpKind::Base { op: bop, perm },
                });
            }
        }

        if base_counts[BaseOp::LoadKInit as usize] > 0 {
            let code = code_iter.next().unwrap();
            let perm = base_variants[BaseOp::LoadK as usize][0].1;
            base_variants[BaseOp::LoadKInit as usize].push((code, perm));
            vops.push(VirtualOp {
                code,
                weight: base_weights[BaseOp::LoadKInit as usize].max(1),
                kind: VirtualOpKind::Base {
                    op: BaseOp::LoadKInit,
                    perm,
                },
            });
        }

        if base_counts[BaseOp::JumpInit as usize] > 0 {
            let code = code_iter.next().unwrap();
            let perm = base_variants[BaseOp::Jump as usize][0].1;
            base_variants[BaseOp::JumpInit as usize].push((code, perm));
            vops.push(VirtualOp {
                code,
                weight: base_weights[BaseOp::JumpInit as usize].max(1),
                kind: VirtualOpKind::Base {
                    op: BaseOp::JumpInit,
                    perm,
                },
            });
        }

        let mut super_encodings = Vec::with_capacity(superop_len);
        if let Some(first_mod) = modules.first() {
            for sdef in &first_mod.superops {
                let code = code_iter.next().unwrap();
                let step_perms: Vec<[usize; 4]> =
                    (0..sdef.pattern.len()).map(|_| rand_perm4(rng)).collect();
                super_encodings.push((code, step_perms.clone()));
                vops.push(VirtualOp {
                    code,
                    weight: super_weights[sdef.id].max(2),
                    kind: VirtualOpKind::Super {
                        super_id: sdef.id,
                        pattern: sdef.pattern.clone(),
                        step_perms,
                    },
                });
            }
        }

        let mut chaff_opcodes = Vec::new();
        for d in 0..decoy_count {
            let code = code_iter.next().unwrap();
            let perm = rand_perm4(rng);
            chaff_opcodes.push(code);
            vops.push(VirtualOp {
                code,
                weight: 0,
                kind: VirtualOpKind::Decoy {
                    variant: (d % 3) as u8,
                    perm,
                },
            });
        }
        for v in &vops {
            chaff_opcodes.push(v.code);
        }

        vops.sort_by_key(|v| v.code);

        let mut proto_sections = [
            ProtoSection::Consts,
            ProtoSection::Upvals,
            ProtoSection::Code,
        ];
        rng.shuffle(&mut proto_sections);

        let mut proto_slots = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        rng.shuffle(&mut proto_slots);

        let mut tag_pool: Vec<u8> = (10u8..=240u8).collect();
        rng.shuffle(&mut tag_pool);
        let const_tags = [
            tag_pool[0],
            tag_pool[1],
            tag_pool[2],
            tag_pool[3],
            tag_pool[4],
        ];
        let upval_tags = (tag_pool[5], tag_pool[6]);
        let lazy_tags = [tag_pool[7], tag_pool[8], tag_pool[9], tag_pool[10]];

        let cipher = StreamCipherSpec {
            s1_init: rng.next_u8_range(1, 254),
            s2_init: rng.next_u8_range(1, 254),
            m1: (rng.next_u8_range(1, 62) * 4) + 1,
            a1: (rng.next_u8_range(1, 126) * 2) + 1,
            m2: (rng.next_u8_range(1, 62) * 4) + 1,
            a2: (rng.next_u8_range(1, 126) * 2) + 1,
        };

        let selfmod_delta = rng.next_u8_range(19, 237);
        let jinit_bias = 109 + rng.next_usize(900) as u32;

        Self {
            ops: vops,
            base_variants,
            super_encodings,
            chaff_opcodes,
            proto_sections,
            proto_slots,
            const_tags,
            lazy_tags,
            upval_tags,
            cipher,
            selfmod_delta,
            jinit_bias,
        }
    }
}

fn rand_perm4(rng: &mut Prng) -> [usize; 4] {
    let mut p = [0, 1, 2, 3];
    rng.shuffle(&mut p);
    p
}
