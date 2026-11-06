use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use wabisabi_cli::{
    compile_luau_to_vm, compile_luau_to_vm_with_seed, compile_luau_with_options, find_luau_binary,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_tmp_dir() -> std::path::PathBuf {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let _ = fs::create_dir_all(&dir);
    dir
}

fn assert_luau_equiv(name: &str, src: &str, args: &[&str]) {
    let luau = find_luau_binary(None).expect("luau.exe must be available for differential tests");
    let (_, vm_src) = compile_luau_to_vm(src)
        .unwrap_or_else(|e| panic!("[{name}] failed to compile Luau source:\n{e}\n--- SRC ---\n{src}"));

    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let tmp = test_tmp_dir();
    let orig_path = tmp.join(format!("ws_diff_{id}_orig.luau"));
    let obf_path = tmp.join(format!("ws_diff_{id}_obf.luau"));

    fs::write(&orig_path, src).unwrap();
    fs::write(&obf_path, &vm_src).unwrap();

    let mut orig_cmd = Command::new(&luau);
    orig_cmd.arg(&orig_path);
    if !args.is_empty() {
        orig_cmd.arg("-a").args(args);
    }
    let orig_out = orig_cmd.output().expect("failed to run luau on original");

    let mut obf_cmd = Command::new(&luau);
    obf_cmd.arg(&obf_path);
    if !args.is_empty() {
        obf_cmd.arg("-a").args(args);
    }
    let obf_out = obf_cmd.output().expect("failed to run luau on obfuscated");

    let _ = fs::remove_file(&orig_path);
    let _ = fs::remove_file(&obf_path);

    let orig_stdout = String::from_utf8_lossy(&orig_out.stdout);
    let obf_stdout = String::from_utf8_lossy(&obf_out.stdout);
    let orig_stderr = String::from_utf8_lossy(&orig_out.stderr);
    let obf_stderr = String::from_utf8_lossy(&obf_out.stderr);

    assert_eq!(
        orig_out.status.code(),
        obf_out.status.code(),
        "[{name}] exit code mismatch!\norig stderr: {orig_stderr}\nobf stderr: {obf_stderr}\n--- VM ---\n{vm_src}"
    );
    assert_eq!(
        orig_stdout, obf_stdout,
        "[{name}] stdout mismatch!\norig stderr: {orig_stderr}\nobf stderr: {obf_stderr}"
    );
}

#[test]
fn diff_arithmetic_and_precedence() {
    assert_luau_equiv(
        "arith_prec",
        r#"
        print(-2 ^ 2, (-2) ^ 2, 2 ^ 3 ^ 2)
        print(17 // 5, -17 // 5, 17 % 5, -17 % 5)
        print(0xFF_00, 0b1010_0101, 1_000_000.5)
        print(1 / 0.0, 1 / -0.0)
        print("a" .. "b" .. "c" .. 123)
        "#,
        &[],
    );
}

#[test]
fn diff_compound_assignments_single_eval() {
    assert_luau_equiv(
        "compound_assign",
        r#"
        local calls = 0
        local t = { 10, 20, 30 }
        local function idx()
            calls += 1
            return 2
        end
        t[idx()] += 5
        t[idx()] *= 3
        t[idx()] //= 4
        local s = "wabi"
        s ..= "-sabi"
        local x = 100
        x -= 25
        x %= 40
        x ^= 2
        x /= 5
        print(calls, t[1], t[2], t[3], s, x)
        "#,
        &[],
    );
}

#[test]
fn diff_if_expressions_and_short_circuit() {
    assert_luau_equiv(
        "if_expr_short_circuit",
        r#"
        local hits = 0
        local function touch(v)
            hits += 1
            return v
        end
        print(false and touch("bad"), true or touch("bad"))
        print(nil or touch("ok1"), 0 and touch("ok2"))
        for i = -1, 2 do
            local label = if i < 0 then "neg" elseif i == 0 then "zero" elseif i == 1 then "one" else "many"
            print(i, label)
        end
        print("hits:", hits)
        "#,
        &[],
    );
}

#[test]
fn diff_interpolated_strings_and_escapes() {
    assert_luau_equiv(
        "interp_strings",
        r#"
        local tostring = "shadowed!"
        local name = "Wabi"
        local n = 42
        local msg = `Hello {name} #{n}, math={ ({ x = 7 }).x * 3 }, \{escaped\} {nil} {true}`
        local raw = "\x41\x00\xFF\u{3BB}\z
                     _trimmed"
        print(tostring, msg, #raw, string.byte(raw, 1, 6))
        "#,
        &[],
    );
}

#[test]
fn diff_luau_types_and_contextual_keywords() {
    assert_luau_equiv(
        "types_and_contextual",
        r#"
        type Pair<A, B> = { first: A, second: B, fn: ((A) -> B)? }
        export type Mode = "fast" | "secure"

        @native
        local function ident<T>(val: T, ...: number): T
            return val :: T
        end

        local type = type(123)
        local export = "exp"
        local continue = 99
        continue += 1
        print(ident("ok", 1, 2), type, export, continue)
        "#,
        &[],
    );
}

#[test]
fn diff_multiple_assignment_order() {
    assert_luau_equiv(
        "multi_assign",
        r#"
        local t = { 10, 20 }
        local i = 1
        i, t[i] = 2, 99
        print("c1:", i, t[1], t[2])

        local a = { 10, 20 }
        local j = 1
        local function bump()
            j = 2
            return 88
        end
        a[j], j = bump(), 3
        print("c2:", j, a[1], a[2])

        local x = 0
        x, x = 1, 2
        print("c3:", x)

        local order = {}
        local function tag(name, val)
            table.insert(order, name)
            return val
        end
        local u = {}
        u[tag("L1", 1)], u[tag("L2", 2)] = tag("R1", 10), tag("R2", 20)
        u[1], u[1] = 77, 88
        print("c4:", table.concat(order, ","), u[1], u[2])
        "#,
        &[],
    );
}

#[test]
fn diff_upvalues_nested_and_per_iteration_closing() {
    assert_luau_equiv(
        "upvalues_closing",
        r#"
        -- 3-level nested closure sharing mutable upvalue cell
        local function outer(init)
            local secret = init
            local function mid(delta)
                return function()
                    secret += delta
                    return secret
                end, function()
                    return secret
                end
            end
            return mid
        end
        local m = outer(10)
        local inc5, read1 = m(5)
        local inc2, read2 = m(2)
        print(inc5(), inc2(), read1(), read2())

        -- Per-iteration closure capture in numeric for
        local fns = {}
        for i = 1, 4 do
            fns[i] = function() return i * 10 end
            i = 999 -- mutating loop var must not break loop counter!
        end
        print("fornum:", fns[1](), fns[2](), fns[3](), fns[4]())

        -- Per-iteration closure capture in generic for
        local gfns = {}
        for k, v in { "a", "b", "c" } do
            gfns[k] = function() return k .. ":" .. v end
        end
        print("forin:", gfns[1](), gfns[2](), gfns[3]())
        "#,
        &[],
    );
}

#[test]
fn diff_loops_break_continue_and_repeat_until_scopes() {
    assert_luau_equiv(
        "loops_continue_repeat",
        r#"
        local out = {}
        for i = 1, 6 do
            if i % 2 == 0 then
                continue
            end
            table.insert(out, i)
        end
        print("odd:", table.concat(out, ","))

        -- repeat-until with continue + local captured in both body and until condition
        local getters = {}
        local n = 0
        repeat
            n += 1
            local snap = n * 100
            getters[n] = function() return snap end
            if n == 2 then
                local inner = -1
                continue
            end
            snap += 1
        until snap > 300

        print("repeat:", n, getters[1](), getters[2](), getters[3]())
        "#,
        &[],
    );
}

#[test]
fn diff_multret_varargs_and_nil_holes() {
    assert_luau_equiv(
        "multret_nil_holes",
        r#"
        local function holes()
            return 10, nil, 30, nil
        end

        local function inspect(...)
            local count = select('#', ...)
            local a, b, c, d, e = ...
            return string.format("n=%d:%s,%s,%s,%s,%s", count, tostring(a), tostring(b), tostring(c), tostring(d), tostring(e))
        end

        print("direct:", inspect(holes()))
        print("prefixed:", inspect("head", holes()))
        print("paren:", inspect((holes())))

        local t1 = { 1, holes() }
        local t2 = { holes(), 99 }
        print("t1:", t1[1], t1[2], t1[3], t1[4], t1[5])
        print("t2:", t2[1], t2[2], t2[3])

        local function forward(first, ...)
            local x, y = ...
            print("va_fixed:", first, x, y, select('#', ...))
            return "wrap", ...
        end
        print("forwarded:", inspect(forward("F", nil, "mid", nil)))
        "#,
        &[],
    );
}

#[test]
fn diff_generalized_iteration_and_coroutines() {
    assert_luau_equiv(
        "gen_iter_coroutines",
        r#"
        -- Plain table generalized iteration
        local sum = 0
        for k, v in { 5, 15, 25 } do
            sum += k * v
        end

        -- Locked metatable with __iter + outer coroutine yielding inside loop!
        local custom = setmetatable({ 3, 6, 9 }, {
            __metatable = "locked",
            __iter = function(self)
                local idx = 0
                return function()
                    idx += 1
                    if self[idx] then
                        return idx, self[idx] * 10
                    end
                    return nil
                end
            end,
        })

        local co = coroutine.create(function(mult)
            for i, val in custom do
                local back = coroutine.yield(i, val * mult)
                sum += back
            end
            return "done", sum
        end)

        local ok1, i1, v1 = coroutine.resume(co, 2)
        local ok2, i2, v2 = coroutine.resume(co, 1)
        local ok3, i3, v3 = coroutine.resume(co, 2)
        local ok4, status, total = coroutine.resume(co, 3)
        print(ok1, i1, v1, ok2, i2, v2, ok3, i3, v3, ok4, status, total)
        "#,
        &[],
    );
}

#[test]
fn diff_methods_metamethods_pcall_and_recursion() {
    assert_luau_equiv(
        "methods_meta_pcall",
        r#"
        local Vec = {}
        Vec.__index = Vec
        function Vec.new(x, y)
            return setmetatable({ x = x, y = y }, Vec)
        end
        function Vec:mag2()
            return self.x * self.x + self.y * self.y
        end
        function Vec.__add(a, b)
            return Vec.new(a.x + b.x, a.y + b.y)
        end
        function Vec.__lt(a, b)
            return a:mag2() < b:mag2()
        end
        function Vec.__le(a, b)
            return a:mag2() <= b:mag2()
        end

        local v1 = Vec.new(3, 4)
        local v2 = Vec.new(1, 2)
        local v3 = v1 + v2
        print("vec:", v3.x, v3.y, v3:mag2(), v1 > v2, v1 >= v2, v2 < v1)

        local function fib(n)
            if n <= 1 then return n end
            return fib(n - 1) + fib(n - 2)
        end
        print("fib10:", fib(10))

        local ok1, r1, r2 = pcall(function(a, b)
            return a + b, a * b
        end, 6, 7)
        local ok2, err2 = pcall(function()
            error("boom_msg", 0)
        end)
        print("pcall:", ok1, r1, r2, ok2, err2)
        "#,
        &[],
    );
}

#[test]
fn diff_cli_vararg_forwarding() {
    assert_luau_equiv(
        "cli_args",
        r#"
        print("argc:", select('#', ...), ...)
        "#,
        &["alpha", "beta", "gamma"],
    );
}

#[test]
fn diff_reentrant_c_callbacks_large_tables_and_shadowing() {
    assert_luau_equiv(
        "reentrant_and_tables",
        r#"
        -- Re-entrant C -> VM callbacks via table.sort and string.gsub
        local items = {
            { name = "pear", score = 20 },
            { name = "apple", score = 50 },
            { name = "plum", score = 20 },
            { name = "fig", score = 90 },
        }
        table.sort(items, function(a, b)
            if a.score ~= b.score then
                return a.score > b.score
            end
            return a.name < b.name
        end)
        local names = {}
        for _, it in items do
            table.insert(names, `{it.name}:{it.score}`)
        end
        print("sorted:", table.concat(names, ","))

        local replaced = string.gsub("v1=12, v2=35, v3=7", "%d+", function(s)
            return tostring((tonumber(s) :: number) * 2 + 1)
        end)
        print("gsub:", replaced)

        -- >32 element table constructor batching + mixed hash keys + trailing multret
        local function tail3()
            return 71, 72, 73
        end
        local big = {
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
            11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
            31, 32, 33, 34, 35, tag = "mid", 36, 37,
            [100] = "hundred",
            tail3()
        }
        print("big:", #big, big[1], big[33], big[37], big[38], big[40], big.tag, big[100])

        -- Lexical shadowing + IIFE chaining + bit32/buffer guest usage
        local x = 10
        do
            local x = x * 3 + 1
            print("inner_x:", x)
        end
        local res = (function(n)
            return function(m)
                return { calc = function(self, k) return bit32.bxor(n + m, k) end }
            end
        end)(100)(28):calc(42)
        print("outer_x_and_iife:", x, res)
        "#,
        &[],
    );
}

#[test]
fn diff_phase2_polymorphic_seeds_superops_and_lua51_compat() {
    let script = r#"
        local secret = "WABISABI_TOP_SECRET_CONST_778899"
        local function compute(limit)
            local acc = 0
            local tbl = {}
            for i = 1, limit do
                local v = (i * 3 + 7) % 97
                tbl[i] = v
                acc = acc + v
            end
            local check = 0
            for k, v in pairs(tbl) do
                check = check + (v - (k % 5))
            end
            return acc, check, string.sub(secret, 1, 8)
        end
        local a, b, tag = compute(120)
        print(a, b, tag)
    "#;

    let luau = find_luau_binary(None).expect("luau.exe required");

    let tmp = test_tmp_dir();
    let orig_path = tmp.join("ws_p2_orig.luau");
    fs::write(&orig_path, script).unwrap();
    let expected_out = Command::new(&luau)
        .arg(&orig_path)
        .output()
        .expect("luau run")
        .stdout;
    let _ = fs::remove_file(&orig_path);

    let mut prev_vm: Option<String> = None;
    for seed in [1u64, 42, 1337, 9999, 0xDEAD_BEEF, 0xCAFE_BABE, 2026, 77777] {
        let (_, vm_code, stats) =
            compile_luau_to_vm_with_seed(script, Some(seed)).expect("compile with seed");
        assert!(
            stats.superop_count > 0,
            "expected superoperator fusion to trigger on loop-heavy script"
        );
        assert!(
            !vm_code.contains("WABISABI_TOP_SECRET_CONST_778899"),
            "plaintext string constant leaked into VM output!"
        );
        if let Some(ref prev) = prev_vm {
            assert_ne!(
                prev, &vm_code,
                "different seeds must produce distinct polymorphic VM code!"
            );
        }
        prev_vm = Some(vm_code.clone());

        let obf_path = tmp.join(format!("ws_p2_seed_{seed}.luau"));
        fs::write(&obf_path, &vm_code).unwrap();

        let luau_o0 = Command::new(&luau).arg("-O0").arg(&obf_path).output().unwrap();
        assert!(
            luau_o0.status.success(),
            "seed {seed} failed on Luau -O0: {}",
            String::from_utf8_lossy(&luau_o0.stderr)
        );
        assert_eq!(luau_o0.stdout, expected_out, "seed {seed} mismatch on Luau -O0");

        let luau_jit = Command::new(&luau)
            .arg("-O2")
            .arg("--codegen")
            .arg(&obf_path)
            .output()
            .unwrap();
        assert!(
            luau_jit.status.success(),
            "seed {seed} failed on Luau -O2 --codegen: {}",
            String::from_utf8_lossy(&luau_jit.stderr)
        );
        assert_eq!(
            luau_jit.stdout, expected_out,
            "seed {seed} mismatch on Luau -O2 --codegen"
        );

        let _ = fs::remove_file(&obf_path);
    }
}

#[test]
fn diff_phase3_antitamper_radix85_ir_obf_and_no_leaks() {
    let script = r#"
        local banner = "PHASE3_HIDDEN_PAYLOAD_9911"
        local magic = 123456
        local other = -654321
        local function verify(x)
            if x == 10 then
                return banner .. ":" .. tostring(magic + other + x)
            end
            return "bad"
        end
        print(verify(10))
    "#;

    let luau = find_luau_binary(None).expect("luau.exe required");
    let tmp = test_tmp_dir();

    let orig_path = tmp.join("ws_p3_orig.luau");
    fs::write(&orig_path, script).unwrap();
    let expected_out = Command::new(&luau)
        .arg(&orig_path)
        .output()
        .expect("luau run")
        .stdout;
    let _ = fs::remove_file(&orig_path);

    let (_, vm_code, _) =
        compile_luau_with_options(script, Some(0x5AB1_5AB1_2026), true).expect("phase3 compile");

    // 1. Two-line release format with polymorphic 1-2 char outer carrier names:
    //    Line 1 = official Wabi Sabi header, Line 2 = `return({<m>=...,<b_or_m>="WABI..."}):<m>()(...)`
    let lines: Vec<&str> = vm_code.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "minified release output must be exactly 2 lines (header comment + 1 executable line)"
    );
    assert_eq!(
        lines[0],
        "-- generated by wabi sabi obfuscator [https://wabisabi.mom/obfuscator]"
    );
    assert!(
        lines[1].starts_with("return({"),
        "executable line must start with `return({{`"
    );
    assert!(
        lines[1].ends_with("()(...)"),
        "executable line must end with `}}):<entry>()(...)`"
    );
    assert!(
        lines[1].contains("=\"WABI"),
        "executable line must carry standard `WABI` ASCII85 armor in a polymorphic 1-2 char field"
    );

    let extract_entry_method = |line: &str| -> String {
        let trimmed = line.strip_suffix("()(...)").expect("tail `()(...)`");
        let colon_pos = trimmed.rfind("}):").expect("tail `}}):`");
        trimmed[colon_pos + 3..].to_string()
    };
    let m0 = extract_entry_method(lines[1]);
    assert!(
        (1..=2).contains(&m0.len()) && m0.chars().all(|c| c.is_ascii_alphabetic()),
        "outer carrier entry method `{m0}` must be 1-2 ASCII letters"
    );

    let mut seen_methods = std::collections::HashSet::new();
    let mut saw_len1 = false;
    let mut saw_len2 = false;
    for s in 1u64..=16 {
        let (_, alt_vm, _) =
            compile_luau_with_options(script, Some(s * 0x9E37_79B9), true).expect("seed compile");
        let alt_l2 = alt_vm.lines().nth(1).unwrap();
        let m = extract_entry_method(alt_l2);
        assert!((1..=2).contains(&m.len()) && m.chars().all(|c| c.is_ascii_alphabetic()));
        if m.len() == 1 {
            saw_len1 = true;
        } else {
            saw_len2 = true;
        }
        seen_methods.insert(m);
    }
    assert!(
        seen_methods.len() >= 8 && saw_len1 && saw_len2,
        "expected polymorphic 1-char and 2-char outer carrier names across seeds, got {seen_methods:?}"
    );

    assert!(
        lines[1].contains("0x") && lines[1].contains("0b"),
        "Moonveil formatter must emit mixed hex (`0x`) and binary (`0b`) integer literals"
    );

    // 2. Zero plaintext leakage of guest constants, forbidden globals, or private VM identifiers (`verify_release.py`)
    for forbidden in [
        "PHASE3_HIDDEN_PAYLOAD_9911",
        "123456",
        "654321",
        "carrierEntry",
        "carrierBlob",
        "error",
        "assert",
        "pcall",
        "xpcall",
        "raise",
        "setmetatable",
        "getmetatable",
        "rawget",
        "rawset",
        "__iter",
        "upvals",
        "protos",
        "consts",
        "_exec",
    ] {
        assert!(
            !vm_code.contains(forbidden),
            "leaked forbidden identifier or string literal `{forbidden}` in Phase 3 output!"
        );
    }

    // 3. Valid single-line output runs identically on Luau `-O0` and `-O2 --codegen`
    let valid_path = tmp.join("ws_p3_valid.luau");
    fs::write(&valid_path, &vm_code).unwrap();
    let luau_ok = Command::new(&luau).arg(&valid_path).output().unwrap();
    assert!(luau_ok.status.success());
    assert_eq!(luau_ok.stdout, expected_out);

    let luau_jit = Command::new(&luau)
        .arg("-O2")
        .arg("--codegen")
        .arg(&valid_path)
        .output()
        .unwrap();
    assert!(luau_jit.status.success());
    assert_eq!(luau_jit.stdout, expected_out);
    let _ = fs::remove_file(&valid_path);

    // 4. Anti-tamper beautifier trap: splitting table fields/functions onto multiple lines breaks decryption!
    let beautified = vm_code.replace("=function(", "=function(\n");
    assert!(
        beautified.lines().count() > 20,
        "simulated beautifier should split single-line VM across multiple lines"
    );
    let tampered_path = tmp.join("ws_p3_tampered.luau");
    fs::write(&tampered_path, &beautified).unwrap();
    let tampered_luau = Command::new(&luau).arg(&tampered_path).output().unwrap();
    assert!(
        !tampered_luau.status.success() || tampered_luau.stdout != expected_out,
        "anti-tamper trap failed: beautified multi-line VM still produced valid output!"
    );
    let _ = fs::remove_file(&tampered_path);

    // 5. `--no-minify` debug mode also works cleanly
    let (_, unminified_vm, _) =
        compile_luau_with_options(script, Some(0x5AB1_5AB1_2026), false).expect("no-minify compile");
    assert!(unminified_vm.lines().count() > 50);
    let unmin_path = tmp.join("ws_p3_unmin.luau");
    fs::write(&unmin_path, &unminified_vm).unwrap();
    let unmin_luau = Command::new(&luau).arg(&unmin_path).output().unwrap();
    assert!(
        unmin_luau.status.success(),
        "--no-minify failed on Luau: {}",
        String::from_utf8_lossy(&unmin_luau.stderr)
    );
    assert_eq!(unmin_luau.stdout, expected_out);
    let _ = fs::remove_file(&unmin_path);
}

#[test]
fn diff_staged_protection_fnv_lazy_consts_hooks_and_selfmod() {
    // Exercises:
    // - Lazy constant materialization: booleans, +0.0 / -0.0, negative floats/ints, short strings,
    //   and >= 600-byte strings (pairwise in-place reduction without `table.concat`)
    // - Self-modifying `LoadKInit` / `JumpInit` with stateful `bit32` CFGs and `KPrep` / `Commit` across loops
    // - C-function reflection catalog hook detection (`table.concat`, `pcall`, `string.byte`)
    let long_seg = "WABI_SABI_LONG_CONSTANT_SEGMENT_0123456789_ABCDEF!".repeat(16); // 800 bytes (>= 600 threshold)
    let script = format!(
        r#"
        local long_str = "{long_seg}"
        local short_str = "short_lazy_const_42"
        local z_pos = 0.0
        local z_neg = -0.0
        local neg_f = -98765.4321
        local b_t, b_f = true, false

        local function run_loop(rounds)
            local total = 0
            local tag = ""
            for i = 1, rounds do
                if b_t and not b_f then
                    total = total + #long_str + #short_str + i
                else
                    total = total - 999
                end
                if i == rounds then
                    tag = string.sub(long_str, 1, 18) .. "|" .. string.sub(long_str, -10) .. "|" .. short_str
                end
            end
            return total, tag, (1 / z_pos > 0), (1 / z_neg < 0), math.floor(neg_f)
        end

        local tot, tg, zp, zn, nf = run_loop(6)
        print(tot, tg, zp, zn, nf)
        "#
    );

    let luau = find_luau_binary(None).expect("luau.exe required");
    let tmp = test_tmp_dir();

    let orig_path = tmp.join("ws_staged_orig.luau");
    fs::write(&orig_path, &script).unwrap();
    let expected_out = Command::new(&luau)
        .arg(&orig_path)
        .output()
        .expect("luau run")
        .stdout;
    let _ = fs::remove_file(&orig_path);

    let (_, vm_code, _) =
        compile_luau_with_options(&script, Some(0x7742_15AB_2026), true).expect("staged compile");

    // Verify WABI protocol header is present in the container blob while zero FNV constants or guest strings leak
    assert!(
        vm_code.contains("\"WABI"),
        "expected WABI 4-byte protocol header in staged container payload"
    );
    assert!(!vm_code.contains("WABI_SABI_LONG_CONSTANT_SEGMENT"));
    assert!(!vm_code.contains("short_lazy_const_42"));
    assert!(!vm_code.contains("84222325"), "FNV-1a constant must not appear in native Lua shell");
    assert!(!vm_code.contains("cbf29ce4"), "FNV-1a constant must not appear in native Lua shell");

    // 1. Normal execution matches identically on Luau `-O0` and `-O2 --codegen`
    let valid_path = tmp.join("ws_staged_valid.luau");
    fs::write(&valid_path, &vm_code).unwrap();
    let luau_ok = Command::new(&luau).arg(&valid_path).output().unwrap();
    assert!(
        luau_ok.status.success(),
        "staged VM failed on Luau: {}",
        String::from_utf8_lossy(&luau_ok.stderr)
    );
    assert_eq!(luau_ok.stdout, expected_out);

    let luau_jit = Command::new(&luau)
        .arg("-O2")
        .arg("--codegen")
        .arg(&valid_path)
        .output()
        .unwrap();
    assert!(
        luau_jit.status.success(),
        "staged VM failed on Luau -O2 --codegen: {}",
        String::from_utf8_lossy(&luau_jit.stderr)
    );
    assert_eq!(luau_jit.stdout, expected_out);
    let _ = fs::remove_file(&valid_path);

    // 2. C-function reflection catalog anti-hook verification on Luau:
    // Replace Line 1 (`-- generated by ...`) with a 1-line hook so Line 2 stays at physical line 2!
    let line2 = vm_code.lines().nth(1).unwrap();
    for (hook_name, hook_line1) in [
        (
            "hook_table_concat",
            "local _tc = table.concat; table.concat = function(...) return _tc(...) end",
        ),
        (
            "hook_pcall",
            "local _pc = pcall; getfenv().pcall = function(...) return _pc(...) end",
        ),
        (
            "hook_sbyte",
            "local _sb = string.byte; string.byte = function(...) return _sb(...) end",
        ),
    ] {
        let luau_hooked = format!("{hook_line1}\n{line2}\n");
        let lh_path = tmp.join(format!("ws_staged_luau_{hook_name}.luau"));
        fs::write(&lh_path, &luau_hooked).unwrap();
        let res_lh = Command::new(&luau).arg(&lh_path).output().unwrap();
        assert!(
            !res_lh.status.success() || res_lh.stdout != expected_out,
            "C-function reflection catalog failed to trap `{hook_name}` on Luau!"
        );
        let _ = fs::remove_file(&lh_path);
    }
}
