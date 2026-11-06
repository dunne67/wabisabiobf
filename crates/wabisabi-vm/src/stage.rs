use crate::prng::Prng;

/// Randomized slot indices inside the shared `helpers` table passed from the Native Shell
/// to the Virtualized Outer Protection VM (bijection over `1..=64` per build).
#[derive(Debug, Clone, Copy)]
pub struct StageSlots {
    pub erase: usize,
    pub lookup: usize,
    pub invoke: usize,
    pub seed_tbl: usize,
    pub line_probe: usize,
    pub step: usize,
    pub step_query: usize,
    pub r_f32: usize,
    pub r_u32: usize,
    pub r_u8: usize,
    pub peek_u8: usize,
    pub poke_u8: usize,
    pub load_inner: usize,
    pub install_lazy: usize,
    pub wrap_run: usize,
}

#[derive(Debug, Clone)]
pub struct StageSpec {
    pub slots: StageSlots,
    pub seed_table_vals: [u32; 9],
    pub init_obs: u32,
    pub init_rolling: u32,
    pub rounds: u32,
    pub word: u32,
    pub step_mul: u32,
    pub step_add: u32,
    pub init_stack: u32,
    pub stack_limit: u32,
    pub nested_limit: u32,
    /// 10 per-build odd multipliers `< 500` and 24-bit addends for the stack/exception kernel.
    pub stack_m: [u32; 10],
    pub stack_a: [u32; 10],
    pub coro_sec1: u32,
    pub coro_sec2: u32,
    pub len_mask: u32,
}

impl StageSpec {
    pub fn generate(rng: &mut Prng) -> Self {
        let mut pool: Vec<usize> = (1..=48).collect();
        rng.shuffle(&mut pool);
        let slots = StageSlots {
            erase: pool[0],
            lookup: pool[1],
            invoke: pool[2],
            seed_tbl: pool[3],
            line_probe: pool[4],
            step: pool[5],
            step_query: pool[6],
            r_f32: pool[7],
            r_u32: pool[8],
            r_u8: pool[9],
            peek_u8: pool[10],
            poke_u8: pool[11],
            load_inner: pool[12],
            install_lazy: pool[13],
            wrap_run: pool[14],
        };

        let mut seed_table_vals = [0u32; 9];
        for slot in &mut seed_table_vals {
            *slot = 0x10_0000 + (rng.next_usize(0xDF_FFFF) as u32);
        }

        let mut stack_m = [0u32; 10];
        let mut stack_a = [0u32; 10];
        for i in 0..10 {
            stack_m[i] = ((rng.next_usize(180) as u32) * 2) + 131; // odd 131..491 (`* 2^24 << 2^53`)
            stack_a[i] = 10_007 + (rng.next_usize(9_000_000) as u32);
        }

        let coro_sec1 = 100_000_000 + (rng.next_usize(700_000_000) as u32);
        let mut coro_sec2 = 100_000_000 + (rng.next_usize(700_000_000) as u32);
        if coro_sec2 == coro_sec1 {
            coro_sec2 += 17;
        }

        let len_mask = ((rng.next_u64() as u32) & 0x7FFF_FFFF) | 0x1305_0101;

        Self {
            slots,
            seed_table_vals,
            init_obs: 100_000 + (rng.next_usize(14_000_000) as u32),
            init_rolling: 100_000 + (rng.next_usize(14_000_000) as u32),
            rounds: 19 + (rng.next_usize(12) as u32),
            word: 10_000 + (rng.next_usize(50_000) as u32),
            step_mul: ((rng.next_usize(150) as u32) * 2) + 151,
            step_add: 5_003 + (rng.next_usize(4_000_000) as u32),
            init_stack: 200_000 + (rng.next_usize(14_000_000) as u32),
            stack_limit: 24 + (rng.next_usize(10) as u32),
            nested_limit: 14 + (rng.next_usize(8) as u32),
            stack_m,
            stack_a,
            coro_sec1,
            coro_sec2,
            len_mask,
        }
    }

    /// Analytically simulates the legitimate execution of the helper rolling accumulator,
    /// recursive stack/exception kernel, 9 mixed `1,0,1,1,1,1,0,1,1` evidence flag domains,
    /// and exact 32-bit limb FNV-1a-64 key derivation.
    /// None of the resulting key words or expected seeds are ever embedded in emitted code!
    pub fn compute_expected_key(&self) -> (u32, u32, [u8; 8]) {
        // 1. Helper rolling accumulator
        let mut obs = self.init_obs as u64;
        let mut rolling = self.init_rolling as u64;
        for idx in 1..=self.rounds {
            let step = (rolling + (idx as u64) * 977) % 65_536;
            obs = (obs * (self.step_mul as u64) + step + (self.step_add as u64)) % 16_777_216;
            rolling = (rolling * 257 + obs + (idx as u64) * 97) % 16_777_216;
        }

        // 2. Recursive stack & xpcall/pcall boundary kernel
        let m = |k: usize| self.stack_m[k] as u64;
        let a = |k: usize| self.stack_a[k] as u64;
        let upd = |s: u64, k: usize| (s * m(k) + a(k)) % 16_777_216;

        let mut s = self.init_stack as u64;
        // At `depth == stack_limit`: `e_bump` (0) + updates 1, 2, 3
        s = upd(s, 0);
        s = upd(s, 1);
        s = upd(s, 2);
        s = upd(s, 3);
        // Unwind to `depth == stack_limit - 1`:
        // First `xpcall(e_bump, ...)`: `e_bump` (0) succeeds -> `successfulCallback` (4, 5)
        s = upd(s, 0);
        s = upd(s, 4);
        s = upd(s, 5);
        // Second `xpcall(fail_cb, nested)`: `fail_cb` mutates (6) then throws -> `nested` runs `nested_limit` frames:
        // `nested_limit - 1` pre-frames mutate (7), base frame calls `e_bump` (0) + failed `pcall` branch (8)
        s = upd(s, 6);
        for _ in 1..self.nested_limit {
            s = upd(s, 7);
        }
        s = upd(s, 0);
        s = upd(s, 8);
        // Unwind `depth = stack_limit - 1` down to `1`: `(stack_limit - 1)` updates (9)
        for _ in 1..self.stack_limit {
            s = upd(s, 9);
        }

        let r32 = rolling as u32;
        let s32 = s as u32;
        let evidence: [u8; 15] = [
            (r32 & 0xFF) as u8,
            ((r32 >> 8) & 0xFF) as u8,
            ((r32 >> 16) & 0xFF) as u8,
            (s32 & 0xFF) as u8,
            ((s32 >> 8) & 0xFF) as u8,
            ((s32 >> 16) & 0xFF) as u8,
            // 9 live probe flag domains (`1, 0, 1, 1, 1, 1, 0, 1, 1`)
            1,
            0,
            1,
            1,
            1,
            1,
            0,
            1,
            1,
        ];

        // 3. FNV-1a-64 in exact 32-bit limbs (offset `0xcbf29ce484222325`, prime `0x100000001b3`)
        let mut low: u64 = 0x8422_2325;
        let mut high: u64 = 0xCBF2_9CE4;
        for &ev in &evidence {
            low ^= ev as u64;
            let product = low * 435;
            high = (high * 435 + low * 256 + (product >> 32)) & 0xFFFF_FFFF;
            low = product & 0xFFFF_FFFF;
        }

        let low32 = low as u32;
        let high32 = high as u32;
        let l_bytes = low32.to_le_bytes();
        let h_bytes = high32.to_le_bytes();
        let key = [
            l_bytes[0], l_bytes[1], l_bytes[2], l_bytes[3], h_bytes[0], h_bytes[1], h_bytes[2],
            h_bytes[3],
        ];
        (low32, high32, key)
    }

    /// Generates the complete Luau source of the Outer Protection Program.
    /// This source is compiled through `wabisabi-syntax` -> `wabisabi-ir` -> `obfuscate_ir`
    /// -> `superops` so all reflection, stack probing, FNV-1a-64 key derivation, inner-chunk
    /// decryption, and lazy constant materialization run as virtualized VM bytecode!
    pub fn emit_outer_luau(&self, lazy_tags: [u8; 4], k_slot: usize) -> String {
        let sl = self.slots;
        let [tag_nil, tag_bool, tag_num, tag_str] = lazy_tags;
        let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9] = self.stack_m;
        let [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9] = self.stack_a;

        format!(
            r#"
local helpers = ...
local mfloor = math.floor
local sbyte = string.byte
local schar = string.char
local ssub = string.sub
local smatch = string.match
local mtoint = math.tointeger

-- Raw table-membership identity check (immune to `__eq` spoofing; preserves nil/false distinction)
local function rawMatch(left, right)
    if left == nil then return right == nil end
    if left ~= left then return right ~= right end
    local m = {{}}
    m[left] = true
    return m[right] == true
end

-- Closed-cell state wrappers & dormant captured-state branches
local function makeCell(v)
    local c = {{ [2] = v, [3] = 2 }}
    c[1] = c
    return c
end
local sharedCells = {{
    makeCell(861645361),
    makeCell(966660282),
    makeCell(806013644),
    makeCell(319562978),
}}
local bankA = {{ [0] = makeCell(1025716783), [1] = sharedCells[1], [2] = sharedCells[2], [3] = sharedCells[3], [4] = makeCell(446396646) }}
local bankB = {{ [0] = makeCell(598558406), [1] = sharedCells[4], [2] = sharedCells[1], [3] = makeCell(417405541) }}

-- Deceptive non-advancing failure sink (wipes state and performs bounded IEEE-754/wideXor churn)
local function wideXor(a, b)
    local val, w = 0, 1
    while a > 0 or b > 0 do
        local la, lb = a % 2, b % 2
        if la ~= lb then val = val + w end
        a, b, w = (a - la) / 2, (b - lb) / 2, w * 2
    end
    return val
end

local core = {{
    [3] = {stack_limit},
    [5] = {init_stack},
    [8] = coroutine.yield,
    [53] = {coro_sec1},
    [54] = {coro_sec2},
}}

local function sinkTrap()
    bankA[0][1][bankA[0][3]] = 250153251
    core[8] = nil
    core[53] = nil
    core[5] = wideXor(core[5] or 32, 0x603028)
    local sink = {{}}
    for idx = 1, 64 do
        local k = wideXor(idx * 257, 0x3028)
        sink[k] = wideXor(k, idx * 65537)
    end
    core[5] = (sink[wideXor(257, 0x3028)] or 7) % 16777216
end

local function guardTrue(cond)
    bankA[1][1][bankA[1][3]] = bankA[1][1][bankA[1][3]] + 3
    if bankA[4][1][bankA[4][3]] == bankA[0][1][bankA[0][3]] then
        local r = {{}}
        r[486] = r[486]()
    end
    if not cond then
        bankB[3][1][bankB[3][3]] = 0
    end
end

local function guardFalse(cond)
    bankB[2][1][bankB[2][3]] = bankB[2][1][bankB[2][3]] + 5
    if not (bankA[2][1][bankA[2][3]] > 0) then
        local r = {{}}
        r[168](r[169])
    end
    if cond then
        bankA[0][1][bankA[0][3]] = bankA[4][1][bankA[4][3]]
    end
end

-- 1. Native C-Function Reflection Catalog & Caller Inspection
local catalog = {{
    {{ coroutine.create, "create" }},
    {{ coroutine.resume, "resume" }},
    {{ coroutine.status, "status" }},
    {{ coroutine.wrap, "wrap" }},
    {{ coroutine.yield, "yield" }},
    {{ error, "error" }},
    {{ getmetatable, "getmetatable" }},
    {{ next, "next" }},
    {{ pcall, "pcall" }},
    {{ rawequal, "rawequal" }},
    {{ rawget, "rawget" }},
    {{ rawset, "rawset" }},
    {{ select, "select" }},
    {{ setmetatable, "setmetatable" }},
    {{ string.byte, "byte" }},
    {{ string.char, "char" }},
    {{ string.find, "find" }},
    {{ string.format, "format" }},
    {{ string.gmatch, "gmatch" }},
    {{ string.gsub, "gsub" }},
    {{ string.match, "match" }},
    {{ string.rep, "rep" }},
    {{ string.sub, "sub" }},
    {{ table.concat, "concat" }},
    {{ table.insert, "insert" }},
    {{ tonumber, "tonumber" }},
    {{ tostring, "tostring" }},
    {{ type, "type" }},
    {{ xpcall, "xpcall" }},
}}
if typeof then
    table.insert(catalog, {{ typeof, "typeof" }})
end
if buffer and type(buffer) == "table" and buffer.create then
    table.insert(catalog, {{ buffer.create, "create" }})
    table.insert(catalog, {{ buffer.readu8, "readu8" }})
    table.insert(catalog, {{ buffer.writeu8, "writeu8" }})
end
if bit32 and type(bit32) == "table" and bit32.bxor then
    table.insert(catalog, {{ bit32.bxor, "bxor" }})
end

local catalogOK = true
if debug and type(debug) == "table" then
    local dinfo = debug.info
    local dget = debug.getinfo
    if type(dinfo) == "function" then
        table.insert(catalog, {{ dinfo, "info" }})
        if type(debug.traceback) == "function" then
            table.insert(catalog, {{ debug.traceback, "traceback" }})
        end
        for i = 1, #catalog do
            local fn, expectedName = catalog[i][1], catalog[i][2]
            local src, ln, actualName, arity, isva, ident = dinfo(fn, "slnaf")
            local ok = rawMatch(type(fn), "function")
                and rawMatch(src, "[C]")
                and rawMatch(ln, -1)
                and rawMatch(actualName, expectedName)
                and rawMatch(arity, 0)
                and rawMatch(isva, true)
                and rawMatch(ident, fn)
            if not ok then catalogOK = false end
        end
    elseif type(dget) == "function" then
        table.insert(catalog, {{ dget, "getinfo" }})
        for i = 1, #catalog do
            local fn = catalog[i][1]
            local info = dget(fn, "S")
            local ok = rawMatch(type(fn), "function")
                and type(info) == "table"
                and rawMatch(info.what, "C")
                and rawMatch(info.linedefined, -1)
            if not ok then catalogOK = false end
        end
    end
end

-- Caller-wrapper `xpcall` self-capturing handler check
do
    local handlerHit = 0
    local selfHandler
    selfHandler = function(err)
        if rawMatch(type(selfHandler), "function") then
            handlerHit = handlerHit + 1
        end
        return err
    end
    local xok = xpcall(function()
        return (nil)()
    end, selfHandler)
    if xok or handlerHit ~= 1 then
        catalogOK = false
    end
end

if not catalogOK then
    sinkTrap()
end

-- 2. Rolling Helper Accumulator (`rolling` & `observedSeed` / `observedCalls`)
local rolling = {init_rolling}
local rounds = {rounds}
local word = {word}
local last = 0
local stepFn = helpers[{h_step}]
for idx = 1, rounds do
    local st = (rolling + idx * 977) % 65536
    last = stepFn(st)
    rolling = (rolling * 257 + last + idx * 97) % 16777216
end
local observedSeed, observedCalls = helpers[{h_step_query}]()

-- 3. Recursive Coroutine Stack & Exception-Boundary Seed Kernel (`core[5]`)
local function eBump()
    core[5] = (core[5] * {m0} + {a0}) % 16777216
end
local function failProbe()
    return (nil)()
end
local recurse
recurse = function(depth)
    if depth == core[3] then
        eBump()
        core[5] = (core[5] * {m1} + {a1}) % 16777216
        core[5] = (core[5] * {m2} + {a2}) % 16777216
        core[5] = (core[5] * {m3} + {a3}) % 16777216
        return
    end
    recurse(depth + 1)
    if depth == core[3] - 1 then
        local first = xpcall(eBump, function()
            core[5] = (core[5] * 32457 + 3746238) % 16777216
        end)
        if first then
            core[5] = (core[5] * {m4} + {a4}) % 16777216
            core[5] = (core[5] * {m5} + {a5}) % 16777216
        else
            core[5] = (core[5] * 301727 + 14513815) % 16777216
            return
        end
        local entries = 0
        local nested
        nested = function()
            entries = entries + 1
            if entries == {nested_limit} then
                eBump()
                if not pcall(failProbe) then
                    core[5] = (core[5] * {m8} + {a8}) % 16777216
                end
                return
            end
            core[5] = (core[5] * {m7} + {a7}) % 16777216
            nested()
        end
        xpcall(function()
            core[5] = (core[5] * {m6} + {a6}) % 16777216
            return (nil)()
        end, nested)
    end
    core[5] = (core[5] * {m9} + {a9}) % 16777216
    return core[5]
end

local coRoot = coroutine.create(recurse)
local coOk = coroutine.resume(coRoot, 1)
if not coOk then
    sinkTrap()
end
local stackSeed = core[5] or 0

-- 4. 15-Byte Runtime Evidence Buffer (6 dynamic seed bytes + 9 mixed `1,0,1,1,1,1,0,1,1` flags)
local evidence = {{
    rolling % 256,
    mfloor(rolling / 256) % 256,
    mfloor(rolling / 65536) % 256,
    stackSeed % 256,
    mfloor(stackSeed / 256) % 256,
    mfloor(stackSeed / 65536) % 256,
}}
local evCursor = 7
local function recordFlag(idx, cond)
    if idx == 2 or idx == 7 then
        guardFalse(cond)
    else
        guardTrue(cond)
    end
    evidence[evCursor] = if cond then 1 else 0
    evCursor = evCursor + 1
end

-- Flags 1 & 2: Wrapped coroutine yields (`1`, `0`)
local wrapped = coroutine.wrap(function()
    if core[8] then
        core[8](core[53])
        core[8](core[54])
    end
end)
local y1 = wrapped()
recordFlag(1, rawMatch(y1, {coro_sec1}))
local y2 = wrapped()
recordFlag(2, not rawMatch(y2, {coro_sec2}))

-- Flags 3, 4, 5 & 6: Single-line native helper error-line parity & live traceback reflection (`1, 1, 1, 1`)
local hErase = helpers[{h_erase}]
local hLookup = helpers[{h_lookup}]
local hInvoke = helpers[{h_invoke}]
local hLineProbe = helpers[{h_line_probe}]
local pSrc, expectedLine, pFn, pTrace = hLineProbe()
local errTargets = {{ hErase, hLookup, hInvoke }}
local firstErrLine = nil
for ti = 1, 3 do
    local okE, msgE = pcall(errTargets[ti])
    local lnE = if not okE and type(msgE) == "string" then tonumber(smatch(msgE, ":(%d+)")) else nil
    if ti == 1 then firstErrLine = lnE end
    recordFlag(ti + 2, lnE ~= nil and rawMatch(lnE, expectedLine))
end
local tbLine = if type(pTrace) == "string" and #pTrace > 0 then tonumber(smatch(pTrace, ":(%d+)")) else expectedLine
local srcMatch = true
if debug and type(debug) == "table" then
    if type(debug.info) == "function" then
        srcMatch = rawMatch(pSrc, debug.info(hErase, "s")) and rawMatch(expectedLine, debug.info(hErase, "l"))
    elseif type(debug.getinfo) == "function" then
        local gi = debug.getinfo(hErase, "S")
        srcMatch = type(gi) == "table" and rawMatch(pSrc, gi.source) and rawMatch(expectedLine, gi.linedefined)
    end
end
recordFlag(6, expectedLine ~= nil and rawMatch(tbLine, expectedLine) and rawMatch(pFn, hLineProbe) and srcMatch and rawMatch(firstErrLine, expectedLine))

-- Flag 7: Environment/seed wrapper table negation (`0`)
local seedTbl = helpers[{h_seed_tbl}]
local wrapper = {{ [3] = seedTbl, [14] = helpers }}
wrapper[18], wrapper[20] = wrapper, wrapper
pcall(setmetatable, wrapper, nil)
recordFlag(7, not wrapper[3])

-- Flag 8: Native 9-element seed table type & length (`1`)
recordFlag(8, rawMatch(type(seedTbl), "table") and rawMatch(#seedTbl, 9))

-- Flag 9: Variadic helper lookup/invoke/erase contract & helper call-count parity (`1`)
local testObj = {{}}
testObj[testObj] = word + 3
local lookOk = rawMatch(hLookup(testObj), word + 3)
local invOk = rawMatch(hInvoke(function() return word end), word)
hErase(testObj)
local eraseOk = rawget(testObj, testObj) == nil
recordFlag(9, lookOk and invOk and eraseOk and rawMatch(observedSeed, last) and rawMatch(observedCalls, rounds) and catalogOK)

-- 5. Portable O(1) Nibble XOR Table + Exact 32-Bit Limb FNV-1a-64 Key Derivation
local nxor = {{}}
for a = 0, 15 do
    for b = 0, 15 do
        local r, p, ta, tb = 0, 1, a, b
        for _ = 1, 4 do
            local ba, bb = ta % 2, tb % 2
            if ba ~= bb then r = r + p end
            ta, tb, p = (ta - ba) / 2, (tb - bb) / 2, p * 2
        end
        nxor[a * 16 + b] = r
    end
end
local function xor8(a, b)
    local al, bl = a % 16, b % 16
    local ah, bh = (a - al) / 16, (b - bl) / 16
    return nxor[ah * 16 + bh] * 16 + nxor[al * 16 + bl]
end
local function xor32(a, b)
    local res, mul = 0, 1
    for _ = 1, 4 do
        local ba, bb = a % 256, b % 256
        res = res + xor8(ba, bb) * mul
        a, b, mul = (a - ba) / 256, (b - bb) / 256, mul * 256
    end
    return res
end

local low, high = 0x84222325, 0xcbf29ce4
for idx = 1, 15 do
    local lo8 = low % 256
    low = (low - lo8) + xor8(lo8, evidence[idx])
    local prod = low * 435
    high = (high * 435 + low * 256 + mfloor(prod / 4294967296)) % 4294967296
    low = prod % 4294967296
end

local keyBytes = {{
    low % 256,
    mfloor(low / 256) % 256,
    mfloor(low / 65536) % 256,
    mfloor(low / 16777216) % 256,
    high % 256,
    mfloor(high / 256) % 256,
    mfloor(high / 65536) % 256,
    mfloor(high / 16777216) % 256,
}}

-- Precompute 8x256 XOR rows so inner-chunk byte decryption is a single O(1) table lookup per byte!
local keyRows = {{}}
for ki = 1, 8 do
    local kb = keyBytes[ki]
    local row = table.create and table.create(256) or {{}}
    for bv = 0, 255 do
        row[bv] = xor8(bv, kb)
    end
    keyRows[ki] = row
end

-- 6. Consume 18 Discarded Preamble Chaff Reads (57 bytes) + Unmask Inner Payload Length
local rf32 = helpers[{h_r_f32}]
local ru32 = helpers[{h_r_u32}]
local ru8 = helpers[{h_r_u8}]
for _ = 1, 5 do rf32() end
for _ = 1, 8 do ru32() end
for _ = 1, 5 do ru8() end
local innerLen = xor32(ru32(), {len_mask})

-- 7. Decrypt Inner User Chunk In-Place in Shared Buffer & Load Prototypes in Lazy Mode
local rawBuf, innerOff = helpers[{h_peek_u8}]()
local bru8, bwu8 = buffer.readu8, buffer.writeu8
for idx = 0, innerLen - 1 do
    local pos = innerOff + idx
    bwu8(rawBuf, pos, keyRows[(idx % 8) + 1][bru8(rawBuf, pos)])
end

local innerProtos, mainIdx, rawPools = helpers[{h_load_inner}]()

-- 8. Outer-VM Lazy Constant Materializer (0-indexed char table + pairwise long-string reduction)
local chars = {{}}
for c = 0, 255 do
    chars[c] = schar(c)
end
local low24 = low % 16777216
local high24 = high % 16777216

local function decodeF64(b1, b2, b3, b4, b5, b6, b7, b8)
    local sign = 1
    if b8 >= 128 then sign = -1; b8 = b8 - 128 end
    local exp = b8 * 16 + mfloor(b7 / 16)
    local hi = (b7 % 16) * 65536 + b6 * 256 + b5
    local lo = b4 * 16777216 + b3 * 65536 + b2 * 256 + b1
    local mant = hi * 4294967296 + lo
    if exp == 0 then
        if mant == 0 then return sign * 0.0 end
        return sign * (mant / 4503599627370496) * (2 ^ -1022)
    elseif exp == 2047 then
        if mant == 0 then return sign * (1 / 0) end
        return 0 / 0
    end
    local v = sign * (1 + mant / 4503599627370496) * (2 ^ (exp - 1023))
    if mtoint and (v ~= 0 or 1 / v > 0) then return mtoint(v) or v end
    return v
end

local function materialize(rec)
    local nonce, enc = rec[1], rec[2]
    local n = #enc
    local dec = table.create and table.create(n) or {{}}
    local stream = (nonce + low24 + high24) % 16777216
    for i = 1, n do
        stream = (stream * 16598013 + 12820163) % 16777216
        dec[i] = xor8(sbyte(enc, i), mfloor(stream / 65536))
    end
    local tag = dec[1]
    if tag == {tag_nil} then
        return nil
    elseif tag == {tag_bool} then
        return not (dec[2] ~= 0)
    elseif tag == {tag_num} then
        local v = decodeF64(dec[2], dec[3], dec[4], dec[5], dec[6], dec[7], dec[8], dec[9])
        if v ~= 0 and v == v then v = -v end
        if mtoint and (v ~= 0 or 1 / v > 0) then v = mtoint(v) or v end
        return v
    elseif tag == {tag_str} then
        local seed = dec[2]
        local slen = n - 2
        if slen == 0 then return "" end
        if slen < 600 then
            local s = ""
            for i = 3, n do
                seed = (seed * 57 + 51) % 256
                s = s .. chars[xor8(xor8(dec[i], seed), 37)]
            end
            return s
        else
            -- In-place pairwise binary reduction (never calls `table.concat`!)
            local arr = table.create and table.create(slen) or {{}}
            for i = 3, n do
                seed = (seed * 57 + 51) % 256
                arr[i - 2] = chars[xor8(xor8(dec[i], seed), 37)]
            end
            local count = slen
            while count > 1 do
                local dst = 1
                for i = 1, count - 1, 2 do
                    arr[dst] = arr[i] .. arr[i + 1]
                    dst = dst + 1
                end
                if count % 2 ~= 0 then
                    arr[dst] = arr[count]
                    dst = dst + 1
                end
                count = dst - 1
            end
            return arr[1]
        end
    end
    return nil
end

for pi = 1, #innerProtos do
    local pl = rawPools[pi]
    innerProtos[pi][{k_slot}] = setmetatable({{}}, {{
        __index = function(t, idx)
            local rec = pl[idx]
            if rec == nil then return nil end
            pl[idx] = nil
            local v = materialize(rec)
            if v ~= nil then rawset(t, idx, v) end
            return v
        end,
    }})
end
helpers[{h_install_lazy}](materialize)
return helpers[{h_wrap_run}](innerProtos, mainIdx, select(2, ...))
"#,
            stack_limit = self.stack_limit,
            init_stack = self.init_stack,
            coro_sec1 = self.coro_sec1,
            coro_sec2 = self.coro_sec2,
            init_rolling = self.init_rolling,
            rounds = self.rounds,
            word = self.word,
            h_step = sl.step,
            h_step_query = sl.step_query,
            m0 = m0,
            a0 = a0,
            m1 = m1,
            a1 = a1,
            m2 = m2,
            a2 = a2,
            m3 = m3,
            a3 = a3,
            m4 = m4,
            a4 = a4,
            m5 = m5,
            a5 = a5,
            m6 = m6,
            a6 = a6,
            m7 = m7,
            a7 = a7,
            m8 = m8,
            a8 = a8,
            m9 = m9,
            a9 = a9,
            nested_limit = self.nested_limit,
            h_erase = sl.erase,
            h_lookup = sl.lookup,
            h_invoke = sl.invoke,
            h_line_probe = sl.line_probe,
            h_seed_tbl = sl.seed_tbl,
            h_r_f32 = sl.r_f32,
            h_r_u32 = sl.r_u32,
            h_r_u8 = sl.r_u8,
            len_mask = self.len_mask,
            h_peek_u8 = sl.peek_u8,
            h_load_inner = sl.load_inner,
            tag_nil = tag_nil,
            tag_bool = tag_bool,
            tag_num = tag_num,
            tag_str = tag_str,
            k_slot = k_slot,
            h_install_lazy = sl.install_lazy,
            h_wrap_run = sl.wrap_run,
        )
    }
}
