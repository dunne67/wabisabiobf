use crate::isa::{PolymorphicIsa, ProtoSection};
use crate::prng::Prng;
use crate::superops::{BaseOp, FusedModule, FusedProto, FusedSlot};
use wabisabi_ir::ir::{Constant, Instr, IrModule, Proto, UpvalDesc};

pub fn logical_operands_with_isa(ins: &Instr, isa: &PolymorphicIsa, rng: &mut Prng) -> [u32; 4] {
    let r = |reg: u16| -> u32 { reg as u32 + 1 };
    let k = |idx: u32| -> u32 { idx + 1 };
    let pc = |idx: u32| -> u32 { idx + 1 };
    let pr = |idx: u32| -> u32 { idx + 1 };
    let uv = |idx: u16| -> u32 { idx as u32 + 1 };

    match *ins {
        Instr::LoadNil { start, count } => [r(start), r(start) + count as u32 - 1, 0, 0],
        Instr::LoadBool { dst, val } => [r(dst), u32::from(val), 0, 0],
        Instr::LoadK { dst, k: k_idx } => [r(dst), k(k_idx), 0, 0],
        Instr::LoadKInit { dst, k: k_idx } => {
            let loadk_op = isa.base_variants[BaseOp::LoadK as usize][0].0;
            let masked = loadk_op.wrapping_add(isa.selfmod_delta) as u32;
            let chaff = rng.next_u8_range(1, 63) as u32;
            [r(dst), k(k_idx), chaff, masked]
        }
        Instr::JumpInit { target } => {
            let jmp_op = isa.base_variants[BaseOp::Jump as usize][0].0;
            let masked = jmp_op.wrapping_add(isa.selfmod_delta) as u32;
            let c1 = rng.next_u8_range(1, 63) as u32;
            let c2 = rng.next_u8_range(1, 63) as u32;
            [pc(target) + isa.jinit_bias, c1, c2, masked]
        }
        Instr::KPrep { dst, k: k_idx } => {
            let c1 = rng.next_u8_range(1, 63) as u32;
            let c2 = rng.next_u8_range(1, 63) as u32;
            [r(dst), k(k_idx), c1, c2]
        }
        Instr::Commit => [
            rng.next_u8_range(1, 63) as u32,
            rng.next_u8_range(1, 63) as u32,
            rng.next_u8_range(1, 63) as u32,
            rng.next_u8_range(1, 63) as u32,
        ],
        Instr::Move { dst, src } => [r(dst), r(src), 0, 0],
        Instr::GetGlobal { dst, name_k } => [r(dst), k(name_k), 0, 0],
        Instr::SetGlobal { src, name_k } => [r(src), k(name_k), 0, 0],
        Instr::GetUpval { dst, uv: u } => [r(dst), uv(u), 0, 0],
        Instr::SetUpval { src, uv: u } => [r(src), uv(u), 0, 0],
        Instr::CloseUpvals { from_reg } => [r(from_reg), 0, 0, 0],
        Instr::Closure { dst, proto } => [r(dst), pr(proto), 0, 0],
        Instr::NewTable { dst, array_hint } => [r(dst), array_hint as u32, 0, 0],
        Instr::GetTable { dst, tbl, key } => [r(dst), r(tbl), r(key), 0],
        Instr::GetField { dst, tbl, key_k } => [r(dst), r(tbl), k(key_k), 0],
        Instr::SetTable { tbl, key, val } => [r(tbl), r(key), r(val), 0],
        Instr::SetField { tbl, key_k, val } => [r(tbl), k(key_k), r(val), 0],
        Instr::SetList {
            tbl,
            src_start,
            count,
            array_offset,
        } => [r(tbl), r(src_start), count as u32, array_offset],
        Instr::SetListMultret {
            tbl,
            src_start,
            array_offset,
        } => [r(tbl), r(src_start), array_offset, 0],
        Instr::SelfMethod {
            base,
            receiver,
            method_k,
        } => [r(base), r(receiver), k(method_k), 0],
        Instr::Add { dst, lhs, rhs }
        | Instr::Sub { dst, lhs, rhs }
        | Instr::Mul { dst, lhs, rhs }
        | Instr::Div { dst, lhs, rhs }
        | Instr::Idiv { dst, lhs, rhs }
        | Instr::Mod { dst, lhs, rhs }
        | Instr::Pow { dst, lhs, rhs }
        | Instr::Concat { dst, lhs, rhs }
        | Instr::CmpEq { dst, lhs, rhs }
        | Instr::CmpNe { dst, lhs, rhs }
        | Instr::CmpLt { dst, lhs, rhs }
        | Instr::CmpLe { dst, lhs, rhs } => [r(dst), r(lhs), r(rhs), 0],
        Instr::ToString { dst, src }
        | Instr::Neg { dst, src }
        | Instr::Not { dst, src }
        | Instr::Len { dst, src } => [r(dst), r(src), 0, 0],
        Instr::Jump { target } => [pc(target), 0, 0, 0],
        Instr::JumpIfTrue { cond, target } | Instr::JumpIfFalse { cond, target } => {
            [r(cond), pc(target), 0, 0]
        }
        Instr::Call {
            base,
            arg_count,
            ret_count,
        } => [
            r(base),
            arg_count as u32,
            ret_count.map(|n| n as u32 + 1).unwrap_or(0),
            0,
        ],
        Instr::CallMultret { base, ret_count } => {
            [r(base), ret_count.map(|n| n as u32 + 1).unwrap_or(0), 0, 0]
        }
        Instr::Vararg { dst, count } => [r(dst), count.map(|n| n as u32 + 1).unwrap_or(0), 0, 0],
        Instr::Return { start, count } => [r(start), count as u32, 0, 0],
        Instr::ReturnMultret { start } => [r(start), 0, 0, 0],
        Instr::ForNumPrep { base, exit_pc } => [r(base), pc(exit_pc), 0, 0],
        Instr::ForNumLoop { base, body_pc } => [r(base), pc(body_pc), 0, 0],
        Instr::IterPrep { base } => [r(base), 2, 0, 0],
        Instr::IterLoop {
            base,
            var_count,
            exit_pc,
        } => [r(base), var_count as u32, pc(exit_pc), 0],
    }
}

pub fn logical_operands_in_proto(
    proto: &Proto,
    ins: &Instr,
    isa: &PolymorphicIsa,
    rng: &mut Prng,
) -> [u32; 4] {
    let mut ops = logical_operands_with_isa(ins, isa, rng);
    if let Instr::IterPrep { base } = *ins {
        let arity = proto
            .code
            .iter()
            .find_map(|cand| match *cand {
                Instr::IterLoop {
                    base: b2,
                    var_count,
                    ..
                } if b2 == base => Some(var_count as u32),
                _ => None,
            })
            .unwrap_or(2)
            .max(1);
        ops[1] = arity;
    }
    ops
}

pub fn collect_iter_arities(modules: &[&IrModule]) -> Vec<u16> {
    let mut arities: Vec<u16> = Vec::new();
    for m in modules {
        for p in &m.protos {
            for ins in &p.code {
                if let Instr::IterLoop { var_count, .. } = *ins {
                    let vc = var_count.max(1);
                    if !arities.contains(&vc) {
                        arities.push(vc);
                    }
                }
            }
        }
    }
    if arities.is_empty() {
        arities.push(2);
    } else {
        arities.sort_unstable();
    }
    arities
}

pub fn apply_perm(logical: [u32; 4], perm: [usize; 4]) -> [u32; 4] {
    let mut phys = [0u32; 4];
    for l in 0..4 {
        phys[perm[l]] = logical[l];
    }
    phys
}

/// Encodes the full 2-stage WABI container:
/// `[ outer_chunk (eager) | 57 discarded preamble bytes | masked u32 inner_len | FNV-encrypted inner_chunk (lazy constants) ]`
/// and applies the per-build 2-state hidden-sum outer container stream cipher.
pub fn encode_staged_container(
    outer_mod: &IrModule,
    outer_fused: &FusedModule,
    inner_mod: &IrModule,
    inner_fused: &FusedModule,
    isa: &PolymorphicIsa,
    fnv_low: u32,
    fnv_high: u32,
    fnv_key: &[u8; 8],
    len_mask: u32,
    rng: &mut Prng,
) -> Vec<u8> {
    let mut container = Vec::new();

    // 1. Eager outer protection chunk at offset 0
    encode_chunk(
        &mut container,
        outer_mod,
        outer_fused,
        isa,
        None,
        rng,
    );

    // 2. 57 discarded preamble chaff bytes: 5x f32 (20B) + 8x i32 (32B) + 5x u8 (5B)
    for _ in 0..5 {
        let f_val = (rng.next_u8_range(1, 250) as f32) * 0.375;
        container.extend_from_slice(&f_val.to_le_bytes());
    }
    for _ in 0..(8 * 4 + 5) {
        container.push(rng.next_u8_range(0, 255));
    }

    // 3. Inner user chunk with per-constant lazy encryption bound to FNV-1a-64 `(fnv_low, fnv_high)`
    let mut inner_bytes = Vec::new();
    encode_chunk(
        &mut inner_bytes,
        inner_mod,
        inner_fused,
        isa,
        Some((fnv_low, fnv_high)),
        rng,
    );

    // Encrypt inner chunk in-place under repeating 8-byte FNV-1a-64 runtime evidence key
    for (idx, b) in inner_bytes.iter_mut().enumerate() {
        *b ^= fnv_key[idx & 7];
    }

    // 4. Masked u32 inner payload byte length + encrypted inner chunk
    let masked_len = (inner_bytes.len() as u32) ^ len_mask;
    container.extend_from_slice(&masked_len.to_le_bytes());
    container.extend_from_slice(&inner_bytes);

    // 5. Outer 2-state hidden-sum container cipher so static Base85 decoding reveals zero strings in either stage
    let c = isa.cipher;
    let mut s1 = c.s1_init;
    let mut s2 = c.s2_init;
    for b in &mut container {
        s1 = s1.wrapping_mul(c.m1).wrapping_add(c.a1);
        s2 = s2.wrapping_mul(c.m2).wrapping_add(s1).wrapping_add(c.a2);
        *b = b.wrapping_add(s1.wrapping_add(s2));
    }

    container
}

fn encode_chunk(
    out: &mut Vec<u8>,
    module: &IrModule,
    fused: &FusedModule,
    isa: &PolymorphicIsa,
    lazy_fnv: Option<(u32, u32)>,
    rng: &mut Prng,
) {
    write_varu32(out, module.protos.len() as u32);
    write_varu32(out, module.main_proto + 1);

    for (p_idx, proto) in module.protos.iter().enumerate() {
        encode_proto(out, proto, &fused.protos[p_idx], isa, lazy_fnv, rng);
    }
}

fn encode_proto(
    out: &mut Vec<u8>,
    proto: &Proto,
    fproto: &FusedProto,
    isa: &PolymorphicIsa,
    lazy_fnv: Option<(u32, u32)>,
    rng: &mut Prng,
) {
    write_varu32(out, proto.num_params as u32);
    out.push(if proto.is_vararg { 1 } else { 0 });
    write_varu32(out, proto.max_regs as u32);

    for &sec in &isa.proto_sections {
        match sec {
            ProtoSection::Consts => {
                if let Some((fnv_low, fnv_high)) = lazy_fnv {
                    encode_consts_lazy(out, proto, isa, fnv_low, fnv_high, rng);
                } else {
                    encode_consts_eager(out, proto, isa);
                }
            }
            ProtoSection::Upvals => encode_upvals(out, proto, isa),
            ProtoSection::Code => encode_code(out, proto, fproto, isa, rng),
        }
    }
}

fn encode_consts_eager(out: &mut Vec<u8>, proto: &Proto, isa: &PolymorphicIsa) {
    write_varu32(out, proto.constants.len() as u32);
    for c in &proto.constants {
        match c {
            Constant::Nil => out.push(isa.const_tags[0]),
            Constant::Bool(false) => out.push(isa.const_tags[1]),
            Constant::Bool(true) => out.push(isa.const_tags[2]),
            Constant::Number(n) => {
                out.push(isa.const_tags[3]);
                out.extend_from_slice(&n.to_le_bytes());
            }
            Constant::String(bytes) => {
                out.push(isa.const_tags[4]);
                write_varu32(out, bytes.len() as u32);
                out.extend_from_slice(bytes);
            }
        }
    }
}

/// Encodes each constant as an opaque `{ nonce, encrypted_record }` entry decoded lazily on first
/// instruction touch by the Outer Protection VM's `materialize` closure:
/// - Booleans are stored logically inverted (`!b`)
/// - Non-zero finite/infinite numbers are stored negated (`-n`), preserving `+0.0`, `-0.0`, and `NaN`
/// - Strings use a random per-string recurrence seed `s = (57 * s + 51) % 256` with `byte ^ s ^ 37`
/// - Entire record is stream-encrypted under `(nonce + (fnv_low & 0xFFFFFF) + (fnv_high & 0xFFFFFF)) % 2^24`
fn encode_consts_lazy(
    out: &mut Vec<u8>,
    proto: &Proto,
    isa: &PolymorphicIsa,
    fnv_low: u32,
    fnv_high: u32,
    rng: &mut Prng,
) {
    write_varu32(out, proto.constants.len() as u32);
    let [tag_nil, tag_bool, tag_num, tag_str] = isa.lazy_tags;

    for c in &proto.constants {
        let nonce = (rng.next_u64() as u32) & 0xFF_FFFF;
        let mut rec = Vec::new();
        match c {
            Constant::Nil => {
                rec.push(tag_nil);
            }
            Constant::Bool(b) => {
                rec.push(tag_bool);
                rec.push(if !*b { 1 } else { 0 });
            }
            Constant::Number(n) => {
                rec.push(tag_num);
                let stored = if *n != 0.0 && !n.is_nan() { -*n } else { *n };
                rec.extend_from_slice(&stored.to_le_bytes());
            }
            Constant::String(bytes) => {
                rec.push(tag_str);
                let mut s = rng.next_u8_range(1, 255);
                rec.push(s);
                for &b in bytes {
                    s = ((s as u32 * 57 + 51) & 0xFF) as u8;
                    rec.push(b ^ s ^ 37);
                }
            }
        }

        let mut stream = ((nonce as u64)
            + ((fnv_low & 0xFF_FFFF) as u64)
            + ((fnv_high & 0xFF_FFFF) as u64))
            % 16_777_216;
        for b in &mut rec {
            stream = (stream * 16_598_013 + 12_820_163) % 16_777_216;
            let mask = ((stream >> 16) & 0xFF) as u8;
            *b ^= mask;
        }

        write_varu32(out, nonce);
        write_varu32(out, rec.len() as u32);
        out.extend_from_slice(&rec);
    }
}

fn encode_upvals(out: &mut Vec<u8>, proto: &Proto, isa: &PolymorphicIsa) {
    write_varu32(out, proto.upvalues.len() as u32);
    for uv in &proto.upvalues {
        match *uv {
            UpvalDesc::ParentLocal(reg) => {
                out.push(isa.upval_tags.0);
                write_varu32(out, reg as u32 + 1);
            }
            UpvalDesc::ParentUpval(parent_uv) => {
                out.push(isa.upval_tags.1);
                write_varu32(out, parent_uv as u32 + 1);
            }
        }
    }
}

fn encode_code(
    out: &mut Vec<u8>,
    proto: &Proto,
    fproto: &FusedProto,
    isa: &PolymorphicIsa,
    rng: &mut Prng,
) {
    write_varu32(out, fproto.slots.len() as u32);
    for slot in &fproto.slots {
        let (op_byte, phys) = match slot {
            FusedSlot::Base { ins, .. } => {
                let bop = BaseOp::from_instr(ins) as usize;
                let variants = &isa.base_variants[bop];
                let pick = if variants.len() == 1 {
                    0
                } else {
                    rng.next_usize(variants.len())
                };
                let (code, perm) = variants[pick];
                (
                    code,
                    apply_perm(logical_operands_in_proto(proto, ins, isa, rng), perm),
                )
            }
            FusedSlot::SuperHead {
                super_id, steps, ..
            } => {
                let (code, ref step_perms) = isa.super_encodings[*super_id];
                (
                    code,
                    apply_perm(
                        logical_operands_in_proto(proto, &steps[0], isa, rng),
                        step_perms[0],
                    ),
                )
            }
            FusedSlot::SuperTail {
                super_id,
                step_offset,
                ins,
            } => {
                let (_, ref step_perms) = isa.super_encodings[*super_id];
                let chaff_idx = rng.next_usize(isa.chaff_opcodes.len());
                let fake_op = isa.chaff_opcodes[chaff_idx];
                (
                    fake_op,
                    apply_perm(
                        logical_operands_in_proto(proto, ins, isa, rng),
                        step_perms[*step_offset],
                    ),
                )
            }
        };

        out.push(op_byte);
        for &val in &phys {
            write_varu32(out, val);
        }
    }
}

pub fn write_varu32(out: &mut Vec<u8>, mut v: u32) {
    while v >= 128 {
        out.push(((v & 0x7F) | 0x80) as u8);
        v >>= 7;
    }
    out.push(v as u8);
}
