use crate::encode::{collect_iter_arities, encode_staged_container};
use crate::isa::{proto_field, PolymorphicIsa, VirtualOp, VirtualOpKind};
use crate::minify::{minify_lua_single_line_with_names, RELEASE_HEADER};
use crate::network::generate_native_network;
use crate::prng::Prng;
use crate::radix85::Radix85;
use crate::stage::StageSpec;
use crate::superops::{build_fused_pair, BaseOp};
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use wabisabi_ir::ir::IrModule;
use wabisabi_ir::{lower_ast, obfuscate_ir};
use wabisabi_syntax::parse_luau;

#[derive(Debug, Clone)]
pub struct EmitOptions {
    pub seed: Option<u64>,
    pub minify: bool,
    /// Optional user-supplied seed words for identifier naming. When set and usable,
    /// all renamed locals/members are drawn from combinations of these words.
    pub names: Option<Vec<String>>,
}

impl Default for EmitOptions {
    fn default() -> Self {
        Self {
            seed: None,
            minify: true,
            names: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EmitStats {
    pub total_vops: usize,
    pub superop_count: usize,
    pub payload_bytes: usize,
}

pub fn emit_luau_vm(module: &IrModule) -> String {
    emit_luau_vm_with_options(module, EmitOptions::default()).0
}

pub fn emit_luau_vm_with_options(inner_module: &IrModule, opts: EmitOptions) -> (String, EmitStats) {
    let seed = opts.seed.unwrap_or_else(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x517C_C1B7_2722_0A95);
        nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (std::process::id() as u64)
    });
    let mut rng = Prng::from_seed(seed);

    // 1. Synthesize per-build Outer Protection Specification & analytical FNV-1a-64 key
    let stage = StageSpec::generate(&mut rng);
    let (fnv_low, fnv_high, fnv_key) = stage.compute_expected_key();

    // 2. Pre-select shuffled prototype column layout & lazy constant wire tags so the
    //    virtualized Outer Protection Chunk references the exact same layout as `isa`.
    let mut tag_pool: Vec<u8> = (1u8..=250).collect();
    rng.shuffle(&mut tag_pool);
    let pre_lazy_tags = [tag_pool[0], tag_pool[1], tag_pool[2], tag_pool[3]];

    let mut pre_proto_slots = [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    rng.shuffle(&mut pre_proto_slots);

    // 3. Compile the Outer Protection Program through `wabisabi-syntax` -> `wabisabi-ir` -> `obfuscate_ir`
    let outer_src = stage.emit_outer_luau(pre_lazy_tags, pre_proto_slots[proto_field::K]);
    let outer_ast = parse_luau(&outer_src).expect("outer protection Luau must parse cleanly");
    let mut outer_ir = lower_ast(&outer_ast).expect("outer protection Luau must lower cleanly");
    let outer_obf_seed = rng.next_u64();
    obfuscate_ir(&mut outer_ir, outer_obf_seed);

    // 4. Discover shared basic-block superoperators & polymorphic ISA across both stages
    let (fused_outer, fused_inner) = build_fused_pair(&outer_ir, inner_module);
    let mut isa = PolymorphicIsa::generate_multi(&[&fused_outer, &fused_inner], &mut rng);
    isa.lazy_tags = pre_lazy_tags;
    isa.proto_slots = pre_proto_slots;

    let iter_arities = collect_iter_arities(&[&outer_ir, inner_module]);

    // 5. Encode the 2-stage container & standard `"WABI"` `z`-compressed ASCII85 armor
    let container_bytes = encode_staged_container(
        &outer_ir,
        &fused_outer,
        inner_module,
        &fused_inner,
        &isa,
        fnv_low,
        fnv_high,
        &fnv_key,
        stage.len_mask,
        &mut rng,
    );
    let (escaped_armor, padded_len) = Radix85::encode_escaped(&container_bytes);

    let stats = EmitStats {
        total_vops: isa.ops.len(),
        superop_count: isa.super_encodings.len(),
        payload_bytes: container_bytes.len(),
    };

    // 6. Synthesize the Native Shell (`LAYOUT.md` + `NATIVE.md` + `NETWORK.md`)
    let mut runtime_body = String::with_capacity(48 * 1024);

    // Prelude aliases (only Luau `PUBLIC_GLOBALS` & `PUBLIC_MEMBERS` — zero private strings!)
    let _ = writeln!(
        runtime_body,
        "local create, pack, unpackValues = table.create, table.pack, table.unpack\n\
         local valueType, toNumber = type, tonumber\n\
         local fmtStr, moveValues, selectCount = string.format, table.move, select\n\
         local newThread, suspend = coroutine.wrap, coroutine.yield\n\
         local observer = nil\n\
         local iterationToken, iteratorFactories = {{}}, {{}}"
    );

    // Coroutine-wrap generalized iterator bridges for every arity used in Outer + Inner chunks
    for &arity in &iter_arities {
        let vars: Vec<String> = (1..=arity).map(|i| format!("v{i}")).collect();
        let var_list = vars.join(", ");
        let _ = writeln!(
            runtime_body,
            "iteratorFactories[{arity}] = function(values)\n\
             \x20   return newThread(function()\n\
             \x20       for {var_list} in values[1], values[2], values[3] do\n\
             \x20           suspend(iterationToken, {var_list})\n\
             \x20       end\n\
             \x20       return iterationToken\n\
             \x20   end)\n\
             end"
        );
    }

    let _ = writeln!(
        runtime_body,
        "local services, helpers, state, native, networkMemo, networkRootEntry\n\
         local obsState, obsCalls = {init_obs}, 0",
        init_obs = stage.init_obs,
    );

    // Build independent helper & factory functions, then permute declaration order per seed (`LAYOUT.md`)
    let fn_advance = String::from(
        "local function advance(thread)\n\
         \x20   local packed = pack(thread())\n\
         \x20   while true do\n\
         \x20       if packed[1] == iterationToken then\n\
         \x20           return unpackValues(packed, 2, packed.n)\n\
         \x20       end\n\
         \x20       packed = pack(thread(suspend(unpackValues(packed, 1, packed.n))))\n\
         \x20   end\n\
         end",
    );

    let fn_close_uvs = String::from(
        "local function closeUpvals(ou, fr)\n\
         \x20   for sl, cell in ou do\n\
         \x20       if sl >= fr then\n\
         \x20           cell[1], cell[2] = { cell[1][sl] }, 1\n\
         \x20           ou[sl] = nil\n\
         \x20       end\n\
         \x20   end\n\
         end",
    );

    let fn_step = format!(
        "local function stepFn(delta)\n\
         \x20   obsCalls += 1\n\
         \x20   obsState = ((obsState * {step_mul}) + (delta or 0) + {step_add}) % 16777216\n\
         \x20   if observer then observer(obsState, obsCalls) end\n\
         \x20   return obsState\n\
         end",
        step_mul = stage.step_mul,
        step_add = stage.step_add,
    );

    let fn_step_query = String::from(
        "local function stepQueryFn()\n\
         \x20   return obsState, obsCalls\n\
         end",
    );

    let fn_net_begin = String::from(
        "local function netBegin(shared)\n\
         \x20   state = shared\n\
         \x20   services = shared[23]\n\
         end",
    );

    let fn_net_memo = String::from(
        "local function netMemo(shared, memo)\n\
         \x20   if observer then observer(shared, memo) end\n\
         \x20   networkMemo = memo\n\
         end",
    );

    let fn_net_proto = String::from(
        "local function netProto(shared, proto)\n\
         \x20   if observer then observer(shared, proto) end\n\
         end",
    );

    // `installFactory` depends on `advance` and `closeUpvals` being in scope, so keep `advance`
    // and `closeUpvals` declared before `installFactory`, while permuting all independent declarations!
    let mut pre_fns = vec![fn_advance, fn_close_uvs];
    rng.shuffle(&mut pre_fns);
    for decl in pre_fns {
        let _ = writeln!(runtime_body, "{decl}");
    }

    let fn_install_factory = build_install_factory(&isa, &mut rng);
    let mut mid_fns = vec![
        fn_step,
        fn_step_query,
        fn_net_begin,
        fn_net_memo,
        fn_net_proto,
        fn_install_factory,
    ];
    rng.shuffle(&mut mid_fns);
    for decl in mid_fns {
        let _ = writeln!(runtime_body, "{decl}");
    }

    // 7. Synthesize single-line polymorphic `native = { ... }` method network
    let net = generate_native_network(
        &isa,
        &stage,
        padded_len,
        "armor",
        "create",
        "pack",
        "unpackValues",
        "stepFn",
        "stepQueryFn",
        "netBegin",
        "netMemo",
        "netProto",
        "installFactory",
        &mut rng,
    );

    // Keep `native = { ... }` on one single physical line so single-line reflection probes
    // (`m_erase`, `m_lookup`, `m_invoke`, `m_line_probe`) pass in both release AND `--no-minify` modes!
    let _ = writeln!(
        runtime_body,
        "native = {net_expr}\n\
         networkRootEntry = native:{root_m}()\n\
         helpers = state[15]\n\
         return networkRootEntry(helpers, ...)",
        net_expr = net.table_expr,
        root_m = net.root_method,
    );

    // 8. Wrap in polymorphic outer carrier; `minify_lua_single_line` parses and renames
    //    `carrierEntry` and `carrierBlob` to 1-2 char names (`a..Z`, `aa..ZZ`).
    let entry_field = format!(
        "    carrierEntry = function(self)\n\
         \x20       local armor, environment = self.carrierBlob, getfenv()\n\
         \x20       return function(...)\n\
         {runtime_body}\
         \x20       end\n\
         \x20   end"
    );
    let blob_field = format!("    carrierBlob = \"{escaped_armor}\"");
    let mut carrier_fields = [entry_field, blob_field];
    if opts.minify {
        rng.shuffle(&mut carrier_fields);
    }
    let wrapped = format!(
        "return ({{\n{}\n}}):carrierEntry()(...)\n",
        carrier_fields.join(",\n")
    );

    let final_code = if opts.minify {
        minify_lua_single_line_with_names(&wrapped, &mut rng, opts.names.as_deref())
    } else {
        format!("{RELEASE_HEADER}\n{wrapped}")
    };

    (final_code, stats)
}

fn build_install_factory(isa: &PolymorphicIsa, rng: &mut Prng) -> String {
    let ps = &isa.proto_slots;
    let mut out = String::with_capacity(24 * 1024);

    let _ = writeln!(
        out,
        "local function installFactory(shared, methods)\n\
         \x20   if observer then observer(methods) end\n\
         \x20   local arithmetic = {{\n\
         \x20       [19] = bit32.bor,\n\
         \x20       [20] = bit32.countrz,\n\
         \x20       [21] = bit32.lshift,\n\
         \x20       [22] = bit32.rshift,\n\
         \x20       [23] = bit32.band,\n\
         \x20       [24] = bit32.countlz,\n\
         \x20       [25] = bit32.bxor,\n\
         \x20       [26] = bit32.rrotate,\n\
         \x20       [27] = bit32.bnot,\n\
         \x20       [28] = bit32.lrotate,\n\
         \x20   }}\n\
         \x20   shared[65] = arithmetic\n\
         \x20   local allocRegs = shared[1]\n\
         \x20   local factoryExport\n\
         \x20   factoryExport = function(prototype, upvalues, protos)\n\
         \x20       local numParams = prototype[{sl_np}]\n\
         \x20       local isVararg = prototype[{sl_va}]\n\
         \x20       local maxRegs = prototype[{sl_mr}]\n\
         \x20       local constants = prototype[{sl_k}]\n\
         \x20       local operations = prototype[{sl_op}]\n\
         \x20       local col0 = prototype[{sl_s0}]\n\
         \x20       local col1 = prototype[{sl_s1}]\n\
         \x20       local col2 = prototype[{sl_s2}]\n\
         \x20       local col3 = prototype[{sl_s3}]\n\
         \x20       return function(...)\n\
         \x20           local registers = allocRegs(maxRegs)\n\
         \x20           local varargTbl, varargLen = nil, 0\n\
         \x20           if not isVararg then\n\
         \x20               if numParams > 0 then\n\
         \x20                   local a1, a2, a3, a4 = ...\n\
         \x20                   registers[1] = a1\n\
         \x20                   if numParams >= 2 then registers[2] = a2 end\n\
         \x20                   if numParams >= 3 then registers[3] = a3 end\n\
         \x20                   if numParams >= 4 then\n\
         \x20                       registers[4] = a4\n\
         \x20                       if numParams > 4 then\n\
         \x20                           local pk = {{ ... }}\n\
         \x20                           for p = 5, numParams do registers[p] = pk[p] end\n\
         \x20                       end\n\
         \x20                   end\n\
         \x20               end\n\
         \x20           else\n\
         \x20               local nin = selectCount(\"#\", ...)\n\
         \x20               if numParams > 0 then\n\
         \x20                   local pk = {{ ... }}\n\
         \x20                   local lim = if nin < numParams then nin else numParams\n\
         \x20                   for p = 1, lim do registers[p] = pk[p] end\n\
         \x20               end\n\
         \x20               if nin > numParams then\n\
         \x20                   varargLen = nin - numParams\n\
         \x20                   varargTbl = {{ selectCount(numParams + 1, ...) }}\n\
         \x20               else\n\
         \x20                   varargTbl = {{}}\n\
         \x20               end\n\
         \x20           end\n\
         \x20           local pc = 1\n\
         \x20           local top = maxRegs\n\
         \x20           local openUpvals = nil\n\
         \x20           local sx, sg = 1, nil\n\
         \x20           local sa, sb, sc, sd = nil, nil, nil, nil\n\
         \x20           local w0, w1, w2 = 0, 0, 0\n\
         \x20           local i1, i2, i3, i4 = 0, 0, 0, 0\n\
         \x20           while true do\n\
         \x20               local instructionPC = pc\n\
         \x20               local operation = operations[instructionPC]\n\
         \x20               pc += 1",
        sl_np = ps[proto_field::NP],
        sl_va = ps[proto_field::VA],
        sl_mr = ps[proto_field::MR],
        sl_k = ps[proto_field::K],
        sl_op = ps[proto_field::OP],
        sl_s0 = ps[proto_field::S0],
        sl_s1 = ps[proto_field::S1],
        sl_s2 = ps[proto_field::S2],
        sl_s3 = ps[proto_field::S3],
    );

    emit_jittered_dispatch_tree(&mut out, &isa.ops, isa, ps, 4, rng);

    let _ = writeln!(
        out,
        "            end\n\
         \x20       end\n\
         \x20   end\n\
         \x20   shared[56] = factoryExport\n\
         end"
    );

    out
}

const COLS: [&str; 4] = ["col0", "col1", "col2", "col3"];

fn emit_jittered_dispatch_tree(
    out: &mut String,
    ops: &[VirtualOp],
    isa: &PolymorphicIsa,
    ps: &[usize; 12],
    indent: usize,
    rng: &mut Prng,
) {
    let pad = "    ".repeat(indent);
    if ops.is_empty() {
        return;
    }
    if ops.len() == 1 {
        emit_vop(out, &ops[0], isa, ps, indent, rng);
        return;
    }

    let total_w: u128 = ops.iter().map(|v| v.weight as u128).sum();
    let mut split = if total_w == 0 {
        ops.len() / 2
    } else {
        let mut best_idx = 1usize;
        let mut best_diff = u128::MAX;
        let mut prefix = 0u128;
        for idx in 1..ops.len() {
            prefix += ops[idx - 1].weight as u128;
            let diff = (prefix * 2).abs_diff(total_w);
            if diff < best_diff {
                best_diff = diff;
                best_idx = idx;
            }
        }
        best_idx
    };

    // Per-seed topological branch jitter (`styling.py`)
    if ops.len() >= 6 {
        let jitter = (rng.next_usize(3) as isize) - 1;
        split = ((split as isize) + jitter).clamp(1, (ops.len() - 1) as isize) as usize;
    }

    let pivot = ops[split].code;
    // Mixed `<` and `>=` branch polarity matching reference `output.lua`
    if rng.next_usize(2) == 0 {
        let _ = writeln!(out, "{pad}if operation < {pivot} then");
        emit_jittered_dispatch_tree(out, &ops[..split], isa, ps, indent + 1, rng);
        let _ = writeln!(out, "{pad}else");
        emit_jittered_dispatch_tree(out, &ops[split..], isa, ps, indent + 1, rng);
        let _ = writeln!(out, "{pad}end");
    } else {
        let _ = writeln!(out, "{pad}if operation >= {pivot} then");
        emit_jittered_dispatch_tree(out, &ops[split..], isa, ps, indent + 1, rng);
        let _ = writeln!(out, "{pad}else");
        emit_jittered_dispatch_tree(out, &ops[..split], isa, ps, indent + 1, rng);
        let _ = writeln!(out, "{pad}end");
    }
}

fn emit_vop(
    out: &mut String,
    vop: &VirtualOp,
    isa: &PolymorphicIsa,
    ps: &[usize; 12],
    indent: usize,
    rng: &mut Prng,
) {
    let p = "    ".repeat(indent);
    match &vop.kind {
        VirtualOpKind::Base { op, perm } => {
            emit_base_step(out, *op, "instructionPC", *perm, isa, ps, indent, false, rng);
        }
        VirtualOpKind::Super {
            pattern,
            step_perms,
            ..
        } => {
            let k = pattern.len();
            let _ = writeln!(out, "{p}pc = instructionPC + {k}");
            for step in 1..k {
                let _ = writeln!(out, "{p}i{step} = instructionPC + {step}");
            }
            for (step, (&bop, &perm)) in pattern.iter().zip(step_perms.iter()).enumerate() {
                let idx_expr = if step == 0 {
                    "instructionPC".to_string()
                } else {
                    format!("i{step}")
                };
                emit_base_step(out, bop, &idx_expr, perm, isa, ps, indent, true, rng);
            }
        }
        VirtualOpKind::Decoy { variant, perm } => {
            let s0 = format!("{}[instructionPC]", COLS[perm[0]]);
            let s1 = format!("{}[instructionPC]", COLS[perm[1]]);
            match variant {
                0 => {
                    let _ = writeln!(
                        out,
                        "{p}w0 = arithmetic[25]({s0}, {s1}); registers[{s0}] = registers[{s1}]"
                    );
                }
                1 => {
                    let _ = writeln!(out, "{p}pc = arithmetic[23]({s0}, 65535)");
                }
                _ => {
                    let _ = writeln!(out, "{p}registers[{s0}] = not registers[{s1}]");
                }
            }
        }
    }
}

/// Generates 3 distinct 16-bit CFG state labels `(l0, l1, l2)` via `rng`.
fn alloc_cfg_labels(rng: &mut Prng) -> (u32, u32, u32) {
    let l0 = 1024 + (rng.next_usize(20000) as u32);
    let mut l1 = 22000 + (rng.next_usize(20000) as u32);
    if l1 == l0 {
        l1 += 17;
    }
    let mut l2 = 43000 + (rng.next_usize(20000) as u32);
    if l2 == l0 || l2 == l1 {
        l2 += 31;
    }
    (l0, l1, l2)
}

/// Emits a 3-block shuffled `while true do` stateful `bit32` (`bxor` + `lrotate`/`rrotate`) CFG.
fn emit_stateful_3block(
    pad: &str,
    l0: u32,
    l1: u32,
    l2: u32,
    b0_work: &str,
    b1_work: &str,
    b2_work: &str,
    rng: &mut Prng,
) -> String {
    let salt1 = 0x1001 + (rng.next_usize(0xE000) as u32);
    let sh1 = 1 + (rng.next_usize(15) as u32);
    let rot1 = (l0 ^ salt1).rotate_left(sh1);
    let corr1 = rot1 ^ l1;

    let salt2 = 0x1001 + (rng.next_usize(0xE000) as u32);
    let sh2 = 1 + (rng.next_usize(15) as u32);
    let rot2 = (l1 ^ salt2).rotate_right(sh2);
    let corr2 = rot2 ^ l2;

    let step0 = format!(
        "{b0_work}; w0 = arithmetic[25](arithmetic[28](arithmetic[25](w0, {salt1}), {sh1}), {corr1})"
    );
    let step1 = format!(
        "{b1_work}; w0 = arithmetic[25](arithmetic[26](arithmetic[25](w0, {salt2}), {sh2}), {corr2})"
    );
    let step2 = format!("{b2_work}; break");

    let mut blocks = [(l0, step0), (l1, step1), (l2, step2)];
    rng.shuffle(&mut blocks);

    format!(
        "{pad}w0 = {l0}\n\
         {pad}while true do\n\
         {pad}    if w0 == {k0} then {s0}\n\
         {pad}    elseif w0 == {k1} then {s1}\n\
         {pad}    elseif w0 == {k2} then {s2}\n\
         {pad}    else break end\n\
         {pad}end\n",
        k0 = blocks[0].0,
        s0 = blocks[0].1,
        k1 = blocks[1].0,
        s1 = blocks[1].1,
        k2 = blocks[2].0,
        s2 = blocks[2].1,
    )
}

#[allow(clippy::too_many_arguments)]
fn emit_base_step(
    out: &mut String,
    op: BaseOp,
    idx_expr: &str,
    perm: [usize; 4],
    isa: &PolymorphicIsa,
    ps: &[usize; 12],
    indent: usize,
    in_superop: bool,
    rng: &mut Prng,
) {
    let p = "    ".repeat(indent);
    let s = |logical: usize| -> String { format!("{}[{idx_expr}]", COLS[perm[logical]]) };
    let (p0, p1, p2, p3) = (s(0), s(1), s(2), s(3));

    let body = match op {
        BaseOp::LoadNil => format!("{p}for r = {p0}, {p1} do registers[r] = nil end\n"),
        BaseOp::LoadBool => format!("{p}registers[{p0}] = ({p1} ~= 0)\n"),
        BaseOp::LoadK => format!("{p}registers[{p0}] = constants[{p1}]\n"),
        BaseOp::LoadKInit => {
            let delta = isa.selfmod_delta;
            let s3_col = COLS[perm[3]];
            if in_superop {
                format!(
                    "{p}operations[{idx_expr}] = ({p3} - {delta}) % 256\n\
                     {p}{s3_col}[{idx_expr}] = 0\n\
                     {p}registers[{p0}] = constants[{p1}]\n"
                )
            } else {
                let (l0, l1, l2) = alloc_cfg_labels(rng);
                let b0 = format!("w1 = ({p3} - {delta}) % 256; sd = constants[{p1}]");
                let b1 = format!("operations[{idx_expr}] = w1; {s3_col}[{idx_expr}] = 0");
                let b2 = format!("registers[{p0}] = sd");
                emit_stateful_3block(&p, l0, l1, l2, &b0, &b1, &b2, rng)
            }
        }
        BaseOp::JumpInit => {
            let bias = isa.jinit_bias;
            let delta = isa.selfmod_delta;
            let s0_col = COLS[perm[0]];
            let s3_col = COLS[perm[3]];
            if in_superop {
                format!(
                    "{p}w1 = {p0} - {bias}\n\
                     {p}{s0_col}[{idx_expr}] = w1\n\
                     {p}operations[{idx_expr}] = ({p3} - {delta}) % 256\n\
                     {p}{s3_col}[{idx_expr}] = 0\n\
                     {p}pc = w1\n"
                )
            } else {
                let (l0, l1, l2) = alloc_cfg_labels(rng);
                let b0 = format!("w1 = {p0} - {bias}; w2 = ({p3} - {delta}) % 256");
                let b1 = format!(
                    "{s0_col}[{idx_expr}] = w1; operations[{idx_expr}] = w2; {s3_col}[{idx_expr}] = 0"
                );
                let b2 = "pc = w1";
                emit_stateful_3block(&p, l0, l1, l2, &b0, &b1, b2, rng)
            }
        }
        BaseOp::KPrep => format!(
            "{p}sx = {p0}\n\
             {p}sg = constants[{p1}]\n"
        ),
        BaseOp::Commit => format!("{p}registers[sx] = sg\n"),
        BaseOp::Move => format!("{p}registers[{p0}] = registers[{p1}]\n"),
        BaseOp::GetGlobal => format!("{p}registers[{p0}] = environment[constants[{p1}]]\n"),
        BaseOp::SetGlobal => format!("{p}environment[constants[{p1}]] = registers[{p0}]\n"),
        BaseOp::GetUpval => format!("{p}sa = upvalues[{p1}]; registers[{p0}] = sa[1][sa[2]]\n"),
        BaseOp::SetUpval => format!("{p}sa = upvalues[{p1}]; sa[1][sa[2]] = registers[{p0}]\n"),
        BaseOp::CloseUpvals => {
            format!("{p}if openUpvals then closeUpvals(openUpvals, {p0}) end\n")
        }
        BaseOp::Closure => format!(
            "{p}sa = protos[{p1}]\n\
             {p}sb = sa[{sl_nuv}]\n\
             {p}sc = nil\n\
             {p}if sb > 0 then\n\
             {p}    sc = allocRegs(sb)\n\
             {p}    sd = sa[{sl_uvm}]\n\
             {p}    w1 = sa[{sl_uvi}]\n\
             {p}    for u = 1, sb do\n\
             {p}        w0 = w1[u]\n\
             {p}        if sd[u] then\n\
             {p}            if not openUpvals then openUpvals = {{}} end\n\
             {p}            w2 = openUpvals[w0]\n\
             {p}            if not w2 then w2 = {{ registers, w0 }}; openUpvals[w0] = w2 end\n\
             {p}            sc[u] = w2\n\
             {p}        else\n\
             {p}            sc[u] = upvalues[w0]\n\
             {p}        end\n\
             {p}    end\n\
             {p}end\n\
             {p}registers[{p0}] = factoryExport(sa, sc, protos)\n",
            sl_nuv = ps[proto_field::NUV],
            sl_uvm = ps[proto_field::UVM],
            sl_uvi = ps[proto_field::UVI],
        ),
        BaseOp::NewTable => format!("{p}registers[{p0}] = allocRegs({p1})\n"),
        BaseOp::GetTable => {
            format!("{p}registers[{p0}] = registers[{p1}][registers[{p2}]]\n")
        }
        BaseOp::GetField => {
            format!("{p}registers[{p0}] = registers[{p1}][constants[{p2}]]\n")
        }
        BaseOp::SetTable => {
            format!("{p}registers[{p0}][registers[{p1}]] = registers[{p2}]\n")
        }
        BaseOp::SetField => {
            format!("{p}registers[{p0}][constants[{p1}]] = registers[{p2}]\n")
        }
        BaseOp::SetList => format!(
            "{p}sa = {p1}\n\
             {p}moveValues(registers, sa, sa + {p2} - 1, {p3} + 1, registers[{p0}])\n"
        ),
        BaseOp::SetListMultret => {
            format!("{p}moveValues(registers, {p1}, top, {p2} + 1, registers[{p0}])\n")
        }
        BaseOp::SelfMethod => format!(
            "{p}sa = {p0}\n\
             {p}sb = registers[{p1}]\n\
             {p}registers[sa + 1] = sb\n\
             {p}registers[sa] = sb[constants[{p2}]]\n"
        ),
        BaseOp::Add => format!("{p}registers[{p0}] = registers[{p1}] + registers[{p2}]\n"),
        BaseOp::Sub => format!("{p}registers[{p0}] = registers[{p1}] - registers[{p2}]\n"),
        BaseOp::Mul => format!("{p}registers[{p0}] = registers[{p1}] * registers[{p2}]\n"),
        BaseOp::Div => format!("{p}registers[{p0}] = registers[{p1}] / registers[{p2}]\n"),
        BaseOp::Idiv => format!("{p}registers[{p0}] = registers[{p1}] // registers[{p2}]\n"),
        BaseOp::Mod => format!("{p}registers[{p0}] = registers[{p1}] % registers[{p2}]\n"),
        BaseOp::Pow => format!("{p}registers[{p0}] = registers[{p1}] ^ registers[{p2}]\n"),
        BaseOp::Concat => format!("{p}registers[{p0}] = registers[{p1}] .. registers[{p2}]\n"),
        BaseOp::ToString => format!("{p}registers[{p0}] = fmtStr(\"%*\", registers[{p1}])\n"),
        BaseOp::Neg => format!("{p}registers[{p0}] = -registers[{p1}]\n"),
        BaseOp::Not => format!("{p}registers[{p0}] = not registers[{p1}]\n"),
        BaseOp::Len => format!("{p}registers[{p0}] = #registers[{p1}]\n"),
        BaseOp::CmpEq => format!("{p}registers[{p0}] = (registers[{p1}] == registers[{p2}])\n"),
        BaseOp::CmpNe => format!("{p}registers[{p0}] = (registers[{p1}] ~= registers[{p2}])\n"),
        BaseOp::CmpLt => format!("{p}registers[{p0}] = (registers[{p1}] < registers[{p2}])\n"),
        BaseOp::CmpLe => format!("{p}registers[{p0}] = (registers[{p1}] <= registers[{p2}])\n"),
        BaseOp::Jump => format!("{p}pc = {p0}\n"),
        BaseOp::JumpIfTrue => format!("{p}if registers[{p0}] then pc = {p1} end\n"),
        BaseOp::JumpIfFalse => format!("{p}if not registers[{p0}] then pc = {p1} end\n"),
        BaseOp::Call => format!(
            "{p}sa = {p0}\n\
             {p}sb = registers[sa]\n\
             {p}sc, sd = {p1}, {p2}\n\
             {p}if sd == 1 then\n\
             {p}    if sc == 0 then sb()\n\
             {p}    elseif sc == 1 then sb(registers[sa + 1])\n\
             {p}    elseif sc == 2 then sb(registers[sa + 1], registers[sa + 2])\n\
             {p}    elseif sc == 3 then sb(registers[sa + 1], registers[sa + 2], registers[sa + 3])\n\
             {p}    else sb(unpackValues(registers, sa + 1, sa + sc)) end\n\
             {p}elseif sd == 2 then\n\
             {p}    if sc == 0 then registers[sa] = (sb())\n\
             {p}    elseif sc == 1 then registers[sa] = (sb(registers[sa + 1]))\n\
             {p}    elseif sc == 2 then registers[sa] = (sb(registers[sa + 1], registers[sa + 2]))\n\
             {p}    elseif sc == 3 then registers[sa] = (sb(registers[sa + 1], registers[sa + 2], registers[sa + 3]))\n\
             {p}    else registers[sa] = (sb(unpackValues(registers, sa + 1, sa + sc))) end\n\
             {p}elseif sd == 0 then\n\
             {p}    w0 = pack(sb(unpackValues(registers, sa + 1, sa + sc)))\n\
             {p}    w1 = w0.n\n\
             {p}    for r = 1, w1 do registers[sa + r - 1] = w0[r] end\n\
             {p}    top = sa + w1 - 1\n\
             {p}else\n\
             {p}    w1 = sd - 1\n\
             {p}    w0 = pack(sb(unpackValues(registers, sa + 1, sa + sc)))\n\
             {p}    for r = 1, w1 do registers[sa + r - 1] = w0[r] end\n\
             {p}end\n"
        ),
        BaseOp::CallMultret => format!(
            "{p}sa = {p0}\n\
             {p}sb = registers[sa]\n\
             {p}sd = {p1}\n\
             {p}if sd == 1 then\n\
             {p}    sb(unpackValues(registers, sa + 1, top))\n\
             {p}elseif sd == 2 then\n\
             {p}    registers[sa] = (sb(unpackValues(registers, sa + 1, top)))\n\
             {p}elseif sd == 0 then\n\
             {p}    w0 = pack(sb(unpackValues(registers, sa + 1, top)))\n\
             {p}    w1 = w0.n\n\
             {p}    for r = 1, w1 do registers[sa + r - 1] = w0[r] end\n\
             {p}    top = sa + w1 - 1\n\
             {p}else\n\
             {p}    w1 = sd - 1\n\
             {p}    w0 = pack(sb(unpackValues(registers, sa + 1, top)))\n\
             {p}    for r = 1, w1 do registers[sa + r - 1] = w0[r] end\n\
             {p}end\n"
        ),
        BaseOp::Vararg => format!(
            "{p}sa, sd = {p0}, {p1}\n\
             {p}if sd == 0 then\n\
             {p}    for j = 1, varargLen do registers[sa + j - 1] = varargTbl[j] end\n\
             {p}    top = sa + varargLen - 1\n\
             {p}else\n\
             {p}    for j = 1, sd - 1 do registers[sa + j - 1] = varargTbl[j] end\n\
             {p}end\n"
        ),
        BaseOp::Return => format!(
            "{p}if openUpvals then closeUpvals(openUpvals, 1) end\n\
             {p}sa, sd = {p0}, {p1}\n\
             {p}if sd == 0 then return\n\
             {p}elseif sd == 1 then return registers[sa]\n\
             {p}elseif sd == 2 then return registers[sa], registers[sa + 1]\n\
             {p}else return unpackValues(registers, sa, sa + sd - 1) end\n"
        ),
        BaseOp::ReturnMultret => format!(
            "{p}if openUpvals then closeUpvals(openUpvals, 1) end\n\
             {p}return unpackValues(registers, {p0}, top)\n"
        ),
        BaseOp::ForNumPrep => format!(
            "{p}sa = {p0}\n\
             {p}sb = registers[sa]\n\
             {p}sc = registers[sa + 1]\n\
             {p}sd = registers[sa + 2]\n\
             {p}if valueType(sb) ~= \"number\" then sb = toNumber(sb) end\n\
             {p}if valueType(sc) ~= \"number\" then sc = toNumber(sc) end\n\
             {p}if valueType(sd) ~= \"number\" then sd = toNumber(sd) end\n\
             {p}if not (sb and sc and sd) then\n\
             {p}    for r = registers[sa], registers[sa + 1], registers[sa + 2] do break end\n\
             {p}end\n\
             {p}registers[sa], registers[sa + 1], registers[sa + 2] = sb, sc, sd\n\
             {p}if (sd > 0 and sb <= sc) or (sd <= 0 and sb >= sc) then\n\
             {p}    registers[sa + 3] = sb\n\
             {p}else\n\
             {p}    pc = {p1}\n\
             {p}end\n"
        ),
        BaseOp::ForNumLoop => format!(
            "{p}sa = {p0}\n\
             {p}if openUpvals then closeUpvals(openUpvals, sa + 3) end\n\
             {p}sd = registers[sa + 2]\n\
             {p}sb = registers[sa] + sd\n\
             {p}sc = registers[sa + 1]\n\
             {p}if (sd > 0 and sb <= sc) or (sd <= 0 and sb >= sc) then\n\
             {p}    registers[sa] = sb\n\
             {p}    registers[sa + 3] = sb\n\
             {p}    pc = {p1}\n\
             {p}end\n"
        ),
        BaseOp::IterPrep => format!(
            "{p}sa = {p0}\n\
             {p}sb = registers[sa]\n\
             {p}if valueType(sb) ~= \"function\" then\n\
             {p}    registers[sa] = advance\n\
             {p}    registers[sa + 1] = iteratorFactories[{p1}]({{ sb, registers[sa + 1], registers[sa + 2] }})\n\
             {p}    registers[sa + 2] = nil\n\
             {p}end\n"
        ),
        BaseOp::IterLoop => format!(
            "{p}sa, sb = {p0}, {p1}\n\
             {p}if sb <= 2 then\n\
             {p}    sc, sd = registers[sa](registers[sa + 1], registers[sa + 2])\n\
             {p}    if sc == nil then\n\
             {p}        pc = {p2}\n\
             {p}    else\n\
             {p}        registers[sa + 2] = sc\n\
             {p}        registers[sa + 3] = sc\n\
             {p}        if sb == 2 then registers[sa + 4] = sd end\n\
             {p}    end\n\
             {p}else\n\
             {p}    sc = pack(registers[sa](registers[sa + 1], registers[sa + 2]))\n\
             {p}    sd = sc[1]\n\
             {p}    if sd == nil then\n\
             {p}        pc = {p2}\n\
             {p}    else\n\
             {p}        registers[sa + 2] = sd\n\
             {p}        for r = 1, sb do registers[sa + 2 + r] = sc[r] end\n\
             {p}    end\n\
             {p}end\n"
        ),
    };
    out.push_str(&body);
}
