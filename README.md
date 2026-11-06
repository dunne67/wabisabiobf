# Wabi Sabi

> A high-performance, multi-stage virtualizing obfuscator for Luau.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021_Edition-orange.svg)](Cargo.toml)
[![Luau](https://img.shields.io/badge/Target-Luau%200.7+-00A2FF.svg)](https://luau.org/)

**Wabi Sabi** is a zero-dependency bytecode-virtualizing compiler and protection toolchain engineered specifically for the [Luau](https://luau.org/) runtime (including Roblox Luau and standalone Luau environments). It transforms Luau source code into an encrypted, multi-stage virtual machine container that executes on a per-build polymorphic architecture.

---

## Architecture & Features

### 1. Custom Register Virtual Machine
- **Flat 3-Address Register Architecture**: Translates Luau abstract syntax trees directly into custom register-based IR with SSA-like register allocation.
- **Polymorphic Opcode Mapping**: Randomizes virtual opcode numbers (`1..=254`) and operand column permutations (`S0..S3`) on every compilation run.
- **Full Luau Semantics**: Preserves strict evaluation order, multret and vararg forwarding, open/closed upvalue cells across nested closures, and table iteration semantics.

### 2. Multi-Stage Staged Protection
- **Outer Protection VM**: A virtualized preamble that computes analytical 64-bit FNV-1a keys from live runtime execution evidence (reflection probes, stack depth, and coroutine boundaries).
- **In-Memory Decryption**: Decrypts guest bytecode in-place within shared memory buffers using 2-state stream ciphers.
- **Lazy Constant Materialization**: Numeric, boolean, and string constants remain encrypted in memory until accessed on-demand through metatable triggers.
- **Self-Modifying Code**: First-execution initializer instructions (`LoadKInit`, `JumpInit`) rewrite their opcodes in-place at runtime.

### 3. Superoperator Fusion
- **Basic-Block Analysis**: Identifies high-frequency straight-line instruction sequences and fuses them into atomic multi-operation handlers.
- **Slot Invariance**: Preserves jump target alignment using chaff-filled physical slots without exposing basic block boundaries.

### 4. Moonveil Single-Line Minifier
- **Scope-Aware Lexical Renaming**: Replaces variables with compact 1–2 character identifiers while preserving parent-child scope isolation and global access.
- **Custom Dictionary Seeding**: Supports user-defined seed words (`names.txt`) to synthesize themed identifiers.
- **Radix85 Armor**: Compacts binary containers using `'z'`-compressed base-85 ASCII encoding.

---

## Getting Started

### Prerequisites

- [Rust](https://rustup.rs/) (1.70+ recommended, 2021 edition)
- *(Optional)* `luau.exe` on your system `PATH` or in `LUAU_PATH` to run integration tests and execute compiled scripts directly.

### Building from Source

```bash
git clone https://github.com/dunne67/wabisabiobf.git
cd wabisabiobf
cargo build --release
```

The resulting binary will be located at `target/release/wabisabi.exe` (or `target/release/wabisabi` on Unix).

---

## Usage

### Compile a Script

```bash
# Basic compilation to minified Luau output
wabisabi compile input.lua -o output.lua

# Compile with a fixed PRNG seed for reproducible builds
wabisabi compile input.lua -o output.lua --seed 1337

# Compile using custom seed words for variable names
wabisabi compile input.lua -o output.lua --names names.txt

# Disable minification (formatted multi-line debug output)
wabisabi compile input.lua -o output.lua --no-minify

# Dump intermediate custom register IR
wabisabi compile input.lua --dump-ir
```

### Run Directly via Luau

```bash
wabisabi run input.lua -- arg1 arg2
```

### Windows Batch Helper

A helper script is provided for quick compilation:

```bat
compile.bat
```

Configure `NAME_STYLE` in `compile.bat` to switch between default 1–2 character names (`DEFAULT`) and dictionary words (`CUSTOM`).

---

## Workspace Structure

The project is structured into four crates:

| Crate | Description |
|---|---|
| [`wabisabi-syntax`](crates/wabisabi-syntax) | Lexer, token definitions, and recursive-descent parser for modern Luau syntax. |
| [`wabisabi-ir`](crates/wabisabi-ir) | Custom register IR definition, AST lowering, control-flow lowering, and cold-path obfuscation passes. |
| [`wabisabi-vm`](crates/wabisabi-vm) | Virtual machine generator, superoperator fusion, multi-stage container encoder, and Moonveil minifier. |
| [`wabisabi-cli`](crates/wabisabi-cli) | Command-line interface and differential verification test suite. |

---

## Testing

Run the full differential regression test suite:

```bash
cargo test
```

The differential test harness verifies byte-for-byte output equivalence between the original source and the obfuscated output across standalone Luau interpreter runs (`-O0`) and native JIT codegen (`-O2 --codegen`).

---

## License

This project is licensed under the [MIT License](LICENSE) — free for personal, educational, and commercial use.
