use crate::isa::{proto_field, PolymorphicIsa, ProtoSection};
use crate::prng::Prng;
use crate::stage::StageSpec;
use std::collections::HashSet;
use std::fmt::Write;

pub struct NativeNetwork {
    /// Single-line `native = { ... }` table literal expression.
    pub table_expr: String,
    /// Method name of the root initializer (`native:<root_method>()`).
    pub root_method: String,
}

struct CalibratedMemo {
    memo_slots: Vec<(u32, i64)>,
    seed_vals: [u32; 9],
    f_bor: String,
    f_bxor: String,
    f_band: String,
    f_bnot: String,
    f_lshift: String,
    f_rshift: String,
    f_seed: String,
    used_keys: HashSet<u32>,
}

impl CalibratedMemo {
    fn alloc_key(&mut self, rng: &mut Prng) -> u32 {
        loop {
            let k = 1024 + (rng.next_usize(30000) as u32);
            if self.used_keys.insert(k) {
                return k;
            }
        }
    }

    /// Synthesizes a reference-shaped nested `bit32` + `memo` + `self.b` expression whose
    /// exact runtime value equals `target`, and registers `(key, target)` in `memo_slots`.
    fn gen_transition(
        &mut self,
        self_var: &str,
        memo_var: &str,
        getter_method: &str,
        target: i64,
        rng: &mut Prng,
    ) -> String {
        let key = self.alloc_key(rng);
        let aux_key = self.alloc_key(rng);

        let idx1 = rng.next_usize(self.memo_slots.len());
        let (mk1, mv1) = self.memo_slots[idx1];
        let idx2 = rng.next_usize(self.memo_slots.len());
        let (mk2, mv2) = self.memo_slots[idx2];

        let sb1 = rng.next_usize(9);
        let sb2 = rng.next_usize(9);
        let sv1 = self.seed_vals[sb1] as u32;
        let sv2 = self.seed_vals[sb2] as u32;

        // Compute auxiliary memo write value in Rust using exact u32 bit32 semantics
        let u_mv1 = (mv1 as i32) as u32;
        let u_mv2 = (mv2 as i32) as u32;
        let x1 = sv1 ^ u_mv1;
        let o1 = x1 | u_mv2;
        let a1 = o1 & sv2;
        let aux_target = (rng.next_usize(50000) as i64) + 17;
        let aux_delta = aux_target - (a1 as i64);

        // Compute primary selector transition value in Rust using exact u32 bit32 semantics
        let sh = (1 + rng.next_usize(5)) as u32;
        let lhs_cmp = mv1 + (sv1 as i64);
        let chosen_val = if lhs_cmp >= mv2 { u_mv2 } else { sv2 };
        let use_lshift = rng.next_usize(2) == 0;
        let shifted = if use_lshift {
            chosen_val.wrapping_shl(sh)
        } else {
            chosen_val >> sh
        };
        let shift_fn = if use_lshift {
            &self.f_lshift
        } else {
            &self.f_rshift
        };
        let inv = !(u_mv1 ^ sv2);
        let core_u32 = inv ^ shifted;
        let main_delta = target - (core_u32 as i64);

        self.memo_slots.push((aux_key, aux_target));
        self.memo_slots.push((key, target));

        let f_band = &self.f_band;
        let f_bor = &self.f_bor;
        let f_bxor = &self.f_bxor;
        let f_bnot = &self.f_bnot;
        let f_seed = &self.f_seed;
        let b1_idx = sb1 + 1;
        let b2_idx = sb2 + 1;

        format!(
            "if (not ((not ({memo_var})[{key}]))) then \
                 u = ({self_var}):{getter_method}({memo_var}, {key}) \
             else \
                 (({memo_var}))[{aux_key}] = (({aux_delta}) + ((({self_var}).{f_band})(((({self_var}).{f_bor})(((({self_var}).{f_bxor})((({self_var}).{f_seed})[{b1_idx}], ({memo_var})[{mk1}])), ({memo_var})[{mk2}])), (({self_var}).{f_seed})[{b2_idx}]))); \
                 u = (({main_delta}) + ((({self_var}).{f_bxor})(((({self_var}).{f_bnot})(((({self_var}).{f_bxor})(({memo_var})[{mk1}], (({self_var}).{f_seed})[{b2_idx}])))), ((({self_var}).{f_l_or_r})((((({memo_var})[{mk1}] + (({self_var}).{f_seed})[{b1_idx}]) >= ({memo_var})[{mk2}]) and ({memo_var})[{mk2}] or (({self_var}).{f_seed})[{b2_idx}]), {sh}))))); \
                 (({memo_var}))[{key}] = (u) \
             end",
            f_l_or_r = shift_fn,
        )
    }
}

fn alloc_field_pool(rng: &mut Prng) -> Vec<String> {
    const ALPHA: &[u8; 52] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut letters = *ALPHA;
    rng.shuffle(&mut letters);
    let mut out = Vec::with_capacity(180);

    // Reserve `q` and `b` for consistent top-level/network root conventions
    let reserved: HashSet<&str> = [
        "q", "b", "do", "if", "in", "or",
    ]
    .into_iter()
    .collect();

    for &c in &letters {
        let s = (c as char).to_string();
        if !reserved.contains(s.as_str()) {
            out.push(s);
        }
    }
    let mut two = Vec::new();
    for s2 in b'0'..=b'9' {
        for &c in &letters {
            let mut s = String::with_capacity(2);
            s.push(c as char);
            s.push(s2 as char);
            if !reserved.contains(s.as_str()) {
                two.push(s);
            }
        }
    }
    rng.shuffle(&mut two);
    out.extend(two);
    out
}

#[allow(clippy::too_many_arguments)]
pub fn generate_native_network(
    isa: &PolymorphicIsa,
    stage: &StageSpec,
    padded_len: usize,
    armor_var: &str,
    tcreate_var: &str,
    tpack_var: &str,
    tunpack_var: &str,
    step_fn_var: &str,
    step_q_var: &str,
    net_begin_fn: &str,
    net_memo_fn: &str,
    net_proto_fn: &str,
    install_factory_fn: &str,
    rng: &mut Prng,
) -> NativeNetwork {
    let mut pool = alloc_field_pool(rng).into_iter();
    let mut next_f = || pool.next().expect("sufficient short field names");

    let root_method = "q".to_string();
    let f_seed = "b".to_string();

    // Primitive & library alias field names on `native`
    let f_bor = next_f();
    let f_countrz = next_f();
    let f_lshift = next_f();
    let f_rshift = next_f();
    let f_band = next_f();
    let f_countlz = next_f();
    let f_bxor = next_f();
    let f_rrotate = next_f();
    let f_bnot = next_f();
    let f_lrotate = next_f();
    let f_bit32 = next_f();

    let f_gsub = next_f();
    let f_sub = next_f();
    let f_byte = next_f();
    let f_char = next_f();
    let f_unpack1 = next_f();
    let f_unpack2 = next_f();
    let f_s_ru32 = next_f();
    let f_s_ru8 = next_f();
    let f_s_rstr = next_f();
    let f_false = next_f();
    let f_nil = next_f();

    // Single-line reflection & variadic helper field names inside `native`
    let m_erase = next_f();
    let m_lookup = next_f();
    let m_invoke = next_f();
    let m_line_probe = next_f();

    // Core loader & state-machine method names on `native`
    let m_memo_get = next_f();
    let m_driver = next_f();
    let m_armor = next_f();
    let m_readers = next_f();
    let m_varint = next_f();
    let m_factory = next_f();
    let m_helpers = next_f();
    let m_chunk = next_f();
    let m_proto = next_f();
    let m_consts = next_f();
    let m_upvals = next_f();
    let m_code = next_f();
    let m_e_kernel = next_f();
    let m_clear_tmp = next_f();

    // Initial memo slots populated at start of `native:q()`
    let mut used_keys = HashSet::new();
    let mut init_memo = Vec::with_capacity(8);
    for _ in 0..8 {
        let k = loop {
            let cand = 512 + (rng.next_usize(30000) as u32);
            if used_keys.insert(cand) {
                break cand;
            }
        };
        let v = (1000 + rng.next_usize(900000)) as i64;
        init_memo.push((k, v));
    }

    let mut cal = CalibratedMemo {
        memo_slots: init_memo.clone(),
        seed_vals: stage.seed_table_vals,
        f_bor: f_bor.clone(),
        f_bxor: f_bxor.clone(),
        f_band: f_band.clone(),
        f_bnot: f_bnot.clone(),
        f_lshift: f_lshift.clone(),
        f_rshift: f_rshift.clone(),
        f_seed: f_seed.clone(),
        used_keys,
    };

    // Distinct state labels for the `m_driver` initialization loop (`X`)
    let mut state_pool: Vec<i64> = (11..125).collect();
    rng.shuffle(&mut state_pool);
    let st_init = state_pool[0];
    let st_armor = state_pool[1];
    let st_readers = state_pool[2];
    let st_factory = state_pool[3];
    let st_helpers = state_pool[4];
    let st_done = state_pool[5];

    let tr_1 = cal.gen_transition("i", "p", &m_memo_get, st_armor, rng);
    let tr_2 = cal.gen_transition("i", "p", &m_memo_get, st_readers, rng);
    let tr_3 = cal.gen_transition("i", "p", &m_memo_get, st_factory, rng);
    let tr_4 = cal.gen_transition("i", "p", &m_memo_get, st_helpers, rng);
    let tr_5 = cal.gen_transition("i", "p", &m_memo_get, st_done, rng);

    let c = isa.cipher;
    let [t_nil, t_false, t_true, t_num, t_str] = isa.const_tags;
    let (uv_local_tag, _) = isa.upval_tags;
    let ps = isa.proto_slots;
    let sl = stage.slots;

    // Non-function fields (pinned positions)
    let seed_elems = stage
        .seed_table_vals
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join(",");

    let non_fn_fields: Vec<(String, String)> = vec![
        (f_bor.clone(), "(bit32).bor".to_string()),
        (f_countrz.clone(), "(bit32).countrz".to_string()),
        (f_lshift.clone(), "(bit32).lshift".to_string()),
        (f_rshift.clone(), "(bit32).rshift".to_string()),
        (f_band.clone(), "(bit32).band".to_string()),
        (f_countlz.clone(), "(bit32).countlz".to_string()),
        (f_bxor.clone(), "(bit32).bxor".to_string()),
        (f_rrotate.clone(), "(bit32).rrotate".to_string()),
        (f_bnot.clone(), "(bit32).bnot".to_string()),
        (f_lrotate.clone(), "(bit32).lrotate".to_string()),
        (f_bit32.clone(), "bit32".to_string()),
        (f_gsub.clone(), "(string).gsub".to_string()),
        (f_sub.clone(), "(string).sub".to_string()),
        (f_byte.clone(), "(string).byte".to_string()),
        (f_char.clone(), "(string).char".to_string()),
        (f_unpack1.clone(), "unpack".to_string()),
        (f_unpack2.clone(), "unpack".to_string()),
        (f_s_ru32.clone(), "\"readu32\"".to_string()),
        (f_s_ru8.clone(), "\"readu8\"".to_string()),
        (f_s_rstr.clone(), "\"readstring\"".to_string()),
        (f_false.clone(), "false".to_string()),
        (f_nil.clone(), "nil".to_string()),
        (f_seed.clone(), format!("{{{seed_elems}}}")),
    ];

    // Build all function-valued fields (shuffled per seed!)
    let mut fn_fields: Vec<(String, String)> = Vec::with_capacity(32);

    // 1. Single-line reflection & variadic helper closures
    fn_fields.push((
        m_erase.clone(),
        "function(...) ((...))[...] = nil end".to_string(),
    ));
    fn_fields.push((
        m_lookup.clone(),
        "function(...) return ((...))[...] end".to_string(),
    ));
    fn_fields.push((
        m_invoke.clone(),
        "function(...) return ((...))() end".to_string(),
    ));
    fn_fields.push((
        m_line_probe.clone(),
        "function() local i, u, p = debug.info(1, \"slf\"); return i, u, p, debug.traceback() end"
            .to_string(),
    ));

    // 2. Memo lookup helper (`c0`)
    fn_fields.push((
        m_memo_get.clone(),
        "function(i, u, p) local a = (u)[p]; return a end".to_string(),
    ));

    // 3. Temporary state cleanup helper (`O`)
    fn_fields.push((
        m_clear_tmp.clone(),
        "function(i, u) ((u))[10] = (nil); ((u))[13] = (nil); (u)[20] = (nil) end".to_string(),
    ));

    // 4. Factory adapter slot (`f9`)
    fn_fields.push((
        m_factory.clone(),
        format!(
            "function(i, u, p) {install_factory_fn}(p, i); (p)[57] = nil; return nil end"
        ),
    ));

    // 5. WABI `z`-ASCII85 + 2-state stream-cipher `buffer` unpacker (`D9`)
    fn_fields.push((
        m_armor.clone(),
        format!(
            "function(i, u) \
                 local p = ((i).{f_gsub})({armor_var}, \"z\", \"!!!!!\"); \
                 local a, I, j = (#p - 4), 0, {{}}; \
                 local l = ((u)[3])({padded_len}); \
                 local P, g = {s1_init}, {s2_init}; \
                 for C = 5, a, 5 do \
                     local T = ((i).{f_sub})(p, C, (C + 4)); \
                     local n = (j)[T]; \
                     if (n == nil) then \
                         local x0, m0, o0, s0, M0 = ((i).{f_byte})(T, 1, 5); \
                         n = (((((x0 - 33) * 52200625) + ((m0 - 33) * 614125)) + ((o0 - 33) * 7225)) + ((s0 - 33) * 85) + (M0 - 33)); \
                         (j)[T] = n \
                     end; \
                     local e0 = n % 256; \
                     local B0 = (n // 256) % 256; \
                     local t0 = (n // 65536) % 256; \
                     local D0 = (n // 16777216) % 256; \
                     P = ((P * {m1}) + {a1}) % 256; g = ((g * {m2}) + P + {a2}) % 256; e0 = (e0 - P - g) % 256; \
                     P = ((P * {m1}) + {a1}) % 256; g = ((g * {m2}) + P + {a2}) % 256; B0 = (B0 - P - g) % 256; \
                     P = ((P * {m1}) + {a1}) % 256; g = ((g * {m2}) + P + {a2}) % 256; t0 = (t0 - P - g) % 256; \
                     P = ((P * {m1}) + {a1}) % 256; g = ((g * {m2}) + P + {a2}) % 256; D0 = (D0 - P - g) % 256; \
                     buffer.writeu32(l, I, (e0 + (B0 * 256) + (t0 * 65536) + (D0 * 16777216))); \
                     I += 4 \
                 end; \
                 ((u))[37] = l; ((u))[6] = 0; \
                 return l \
             end",
            s1_init = c.s1_init,
            s2_init = c.s2_init,
            m1 = c.m1,
            a1 = c.a1,
            m2 = c.m2,
            a2 = c.a2,
        ),
    ));

    // 6. LEB128 varint reader installer (`W9`) + scalar `buffer` readers (`s9`)
    fn_fields.push((
        m_varint.clone(),
        "function(i, u) \
             (u)[48] = function() \
                 local p, a = 0, 1; \
                 while true do \
                     local I = ((u)[40])(); \
                     if (I < 128) then return (p + (I * a)) end; \
                     p += ((I - 128) * a); \
                     a *= 128 \
                 end \
             end; \
             return nil \
         end"
            .to_string(),
    ));

    fn_fields.push((
        m_readers.clone(),
        format!(
            "function(i, u, p) \
                 (u)[40] = function() local a = (u)[6]; (u)[6] = (a + 1); return ((u)[5])((u)[37], a) end; \
                 ((u))[46] = function() local a = (u)[6]; (u)[6] = (a + 4); return ((p)[(i).{f_s_ru32}])((u)[37], a) end; \
                 ((u))[50] = function() local a = (u)[6]; (u)[6] = (a + 4); return ((p).readf32)((u)[37], a) end; \
                 ((u))[51] = function() local a = (u)[6]; (u)[6] = (a + 8); return ((p).readf64)((u)[37], a) end; \
                 ((u))[52] = function() local a = ((u)[48])(); local I = (u)[6]; (u)[6] = (I + a); return ((p)[(i).{f_s_rstr}])((u)[37], I, a) end; \
                 (i):{m_varint}(u); \
                 return nil \
             end"
        ),
    ));

    // 7. Public `helpers` table wiring (`S0`)
    fn_fields.push((
        m_helpers.clone(),
        format!(
            "function(i, u) \
                 local p = (u)[15]; \
                 (p)[{h_erase}] = (i).{m_erase}; \
                 ((p))[{h_lookup}] = (i).{m_lookup}; \
                 ((p))[{h_invoke}] = (i).{m_invoke}; \
                 ((p))[{h_line_probe}] = (i).{m_line_probe}; \
                 ((p))[{h_seed_tbl}] = (i).{f_seed}; \
                 ((p))[{h_step}] = {step_fn_var}; \
                 ((p))[{h_step_query}] = {step_q_var}; \
                 ((p))[{h_rf32}] = (u)[50]; \
                 ((p))[{h_ru32}] = (u)[46]; \
                 ((p))[{h_ru8}] = (u)[40]; \
                 ((p))[{h_peek}] = function() return (u)[37], (u)[6] end; \
                 ((p))[{h_load_inner}] = function() return (i):{m_chunk}(u, true) end; \
                 ((p))[{h_install_lazy}] = function(a) (u)[60] = a end; \
                 ((p))[{h_wrap_run}] = function(a, I, ...) local j = ((u)[56])((a)[I], {{}}, a); return j(...) end; \
                 return p \
             end",
            h_erase = sl.erase,
            h_lookup = sl.lookup,
            h_invoke = sl.invoke,
            h_line_probe = sl.line_probe,
            h_seed_tbl = sl.seed_tbl,
            h_step = sl.step,
            h_step_query = sl.step_query,
            h_rf32 = sl.r_f32,
            h_ru32 = sl.r_u32,
            h_ru8 = sl.r_u8,
            h_peek = sl.peek_u8,
            h_load_inner = sl.load_inner,
            h_install_lazy = sl.install_lazy,
            h_wrap_run = sl.wrap_run,
        ),
    ));

    // 8. Memoized state-machine initialization driver (`X`)
    fn_fields.push((
        m_driver.clone(),
        format!(
            "function(i, u, p, a, I) \
                 while true do \
                     if (u == {st_init}) then \
                         (I)[1] = {tcreate_var}; ((I))[2] = {tunpack_var}; ((I))[3] = (a).create; \
                         ((I))[5] = ((a)[(i).{f_s_ru8}]); ((I))[6] = 0; ((I))[15] = {{}}; \
                         ((I))[23] = {{}}; ((I))[55] = {tpack_var}; ((I))[74] = function() end; \
                         {tr_1}; continue \
                     else \
                         if (u == {st_armor}) then \
                             (i):{m_armor}(I); \
                             {tr_2}; continue \
                         else \
                             if (u == {st_readers}) then \
                                 (i):{m_readers}(I, a); \
                                 {tr_3}; continue \
                             else \
                                 if (u == {st_factory}) then \
                                     (i):{m_factory}(nil, I); \
                                     {tr_4}; continue \
                                 else \
                                     if (u == {st_helpers}) then \
                                         (i):{m_helpers}(I); \
                                         {tr_5}; continue \
                                     else \
                                         if (u == {st_done}) then \
                                             (i):{m_clear_tmp}(I); break \
                                         end \
                                     end \
                                 end \
                             end \
                         end \
                     end \
                 end; \
                 return nil \
             end"
        ),
    ));

    // 9. Constant section loader (`n0`)
    fn_fields.push((
        m_consts.clone(),
        format!(
            "function(i, u, p) \
                 local a = ((u)[48])(); \
                 if p then \
                     local I = ((u)[1])(a); \
                     for j = 1, a, 1 do \
                         local l = ((u)[48])(); \
                         local P = ((u)[52])(); \
                         (I)[j] = {{ l, P }} \
                     end; \
                     return {{}}, I \
                 else \
                     local I = ((u)[1])(a); \
                     for j = 1, a, 1 do \
                         local l = ((u)[40])(); \
                         if (l == {t_false}) then (I)[j] = false \
                         elseif (l == {t_true}) then (I)[j] = true \
                         elseif (l == {t_num}) then (I)[j] = ((u)[51])() \
                         elseif (l == {t_str}) then (I)[j] = ((u)[52])() \
                         elseif (l == {t_nil}) then (I)[j] = nil end \
                     end; \
                     return I, nil \
                 end \
             end"
        ),
    ));

    // 10. Upvalue section loader (`u9`)
    fn_fields.push((
        m_upvals.clone(),
        format!(
            "function(i, u) \
                 local p = ((u)[48])(); \
                 local a, I = ((u)[1])(p), ((u)[1])(p); \
                 for j = 1, p, 1 do \
                     (a)[j] = (((u)[40])() == {uv_local_tag}); \
                     ((I))[j] = ((u)[48])() \
                 end; \
                 return p, a, I \
             end"
        ),
    ));

    // 11. Code section loader (`Z0`)
    fn_fields.push((
        m_code.clone(),
        "function(i, u) \
             local p = ((u)[48])(); \
             local a = (u)[1]; \
             local I, j, l, P, g = a(p), a(p), a(p), a(p), a(p); \
             local C = (u)[48]; \
             for T = 1, p, 1 do \
                 (I)[T] = ((u)[40])(); \
                 ((j))[T] = C(); \
                 ((l))[T] = C(); \
                 ((P))[T] = C(); \
                 ((g))[T] = C() \
             end; \
             return I, j, l, P, g \
         end"
            .to_string(),
    ));

    // 12. Prototype reader (`l0`) respecting per-build `isa.proto_sections` & `isa.proto_slots`
    let mut sec_stmts = String::new();
    for &sec in &isa.proto_sections {
        match sec {
            ProtoSection::Consts => {
                let _ = write!(sec_stmts, "j, l = (i):{m_consts}(u, p); ");
            }
            ProtoSection::Upvals => {
                let _ = write!(sec_stmts, "P, g, C = (i):{m_upvals}(u); ");
            }
            ProtoSection::Code => {
                let _ = write!(sec_stmts, "T, n, x0, m0, o0 = (i):{m_code}(u); ");
            }
        }
    }
    let mut slot_exprs = [""; 12];
    slot_exprs[ps[proto_field::NP] - 1] = "a";
    slot_exprs[ps[proto_field::VA] - 1] = "I";
    slot_exprs[ps[proto_field::MR] - 1] = "s0";
    slot_exprs[ps[proto_field::K] - 1] = "j";
    slot_exprs[ps[proto_field::NUV] - 1] = "P";
    slot_exprs[ps[proto_field::UVM] - 1] = "g";
    slot_exprs[ps[proto_field::UVI] - 1] = "C";
    slot_exprs[ps[proto_field::OP] - 1] = "T";
    slot_exprs[ps[proto_field::S0] - 1] = "n";
    slot_exprs[ps[proto_field::S1] - 1] = "x0";
    slot_exprs[ps[proto_field::S2] - 1] = "m0";
    slot_exprs[ps[proto_field::S3] - 1] = "o0";
    let proto_tuple = slot_exprs.join(", ");

    fn_fields.push((
        m_proto.clone(),
        format!(
            "function(i, u, p) \
                 local a = ((u)[48])(); \
                 local I = (((u)[40])() ~= 0); \
                 local s0 = ((u)[48])(); \
                 local j, l, P, g, C, T, n, x0, m0, o0; \
                 {sec_stmts}\
                 local M0 = {{ {proto_tuple} }}; \
                 {net_proto_fn}(u, M0); \
                 return M0, l \
             end"
        ),
    ));

    // 13. Chunk loader (`G0`)
    fn_fields.push((
        m_chunk.clone(),
        format!(
            "function(i, u, p) \
                 (u)[4] = p; \
                 local a = ((u)[48])(); \
                 local I = ((u)[48])(); \
                 local j = ((u)[1])(a); \
                 local l = (p and ((u)[1])(a)) or nil; \
                 for P = 1, a, 1 do \
                     local g, C = (i):{m_proto}(u, p); \
                     (j)[P] = g; \
                     if p then (l)[P] = C end \
                 end; \
                 return j, I, l \
             end"
        ),
    ));

    // 14. Reference-shaped `E` multi-write 24-bit affine step closure (`E`)
    {
        let mut e_body = String::from("function(i) local u = (i)[0]; return function() local p, a; ");
        for _ in 0..8 {
            let mul = 0x10001 + (rng.next_usize(0xE0000) as u32) | 1;
            let add = 0x4000 + (rng.next_usize(0xF00000) as u32);
            let _ = write!(
                e_body,
                "p = {mul}; a = (u)[5]; p = (p * a); a = {add}; p = (p + a); a = 16777216; p = (p % a); ((u))[5] = p; "
            );
        }
        e_body.push_str("return (u)[5] end end");
        fn_fields.push((m_e_kernel.clone(), e_body));
    }

    // 15. Connected decoy state/memo methods on `native` for authentic reference method density
    let decoy_count = 10 + rng.next_usize(5);
    let mut decoy_names = Vec::with_capacity(decoy_count);
    for _ in 0..decoy_count {
        decoy_names.push(next_f());
    }
    for idx in 0..decoy_count {
        let dn = decoy_names[idx].clone();
        let peer = &decoy_names[(idx + 1) % decoy_count];
        let k1 = cal.alloc_key(rng);
        let k2 = cal.alloc_key(rng);
        let c1 = 16 + rng.next_usize(96);
        let c2 = 1024 + rng.next_usize(48000);
        let b_idx = 1 + rng.next_usize(9);
        let body = if idx % 2 == 0 {
            format!(
                "function(i, u, p, a) \
                     if (p == {c1}) then ((a))[{k1}] = (nil); return {c2}, p \
                     else p = {c1}; if (not (u)[{k2}]) then p = (((i).{f_bxor})(((u)[{k1}] or {c2}), ((i).{f_seed})[{b_idx}])); ((u))[{k2}] = p else p = (i):{m_memo_get}(u, {k2}) end; return {c2}, p end \
                 end"
            )
        } else {
            format!(
                "function(i, u, p, a) \
                     repeat \
                         if (p > {c1}) then p = (i):{peer}(u, p, a); break \
                         else ((u))[{k1}] = (((i).{f_band})((p + ((i).{f_seed})[{b_idx}]), {c2})); p = ({c1} + 7) end \
                     until false; \
                     return nil, p \
                 end"
            )
        };
        fn_fields.push((dn, body));
    }

    // 16. Root network entry method (`q`)
    let mut memo_inits = String::new();
    for &(mk, mv) in &init_memo {
        let _ = write!(memo_inits, "(p)[{mk}] = {mv}; ");
    }
    fn_fields.push((
        root_method.clone(),
        format!(
            "function(i) \
                 local u, p = {{}}, {{}}; \
                 {memo_inits}\
                 {net_begin_fn}(u); \
                 {net_memo_fn}(u, p); \
                 (i):{m_driver}({st_init}, p, buffer, u); \
                 local a, I = (i):{m_chunk}(u, false); \
                 return ((u)[56])((a)[I], {{}}, a) \
             end"
        ),
    ));

    // Permute all function-valued fields per seed while keeping non-function fields at fixed indices (`LAYOUT.md`)
    rng.shuffle(&mut fn_fields);

    let total_fields = non_fn_fields.len() + fn_fields.len();
    let mut all_entries = Vec::with_capacity(total_fields);
    let mut fn_iter = fn_fields.into_iter();
    let mut non_fn_iter = non_fn_fields.into_iter();
    for idx in 0..total_fields {
        if idx % 3 == 0 {
            if let Some((k, v)) = non_fn_iter.next() {
                all_entries.push(format!("{k}={v}"));
                continue;
            }
        }
        if let Some((k, v)) = fn_iter.next() {
            all_entries.push(format!("{k}={v}"));
        } else if let Some((k, v)) = non_fn_iter.next() {
            all_entries.push(format!("{k}={v}"));
        }
    }

    let table_expr = format!("{{ {} }}", all_entries.join(", "));
    NativeNetwork {
        table_expr,
        root_method,
    }
}
