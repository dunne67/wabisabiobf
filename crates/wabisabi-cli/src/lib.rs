use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wabisabi_ir::ir::IrModule;
use wabisabi_ir::{lower_ast, obfuscate_ir};
use wabisabi_syntax::parse_luau;
use wabisabi_vm::{emit_luau_vm_with_options, EmitOptions, EmitStats};

pub fn compile_luau_to_vm(source: &str) -> Result<(IrModule, String), String> {
    let (ir, vm, _) = compile_luau_with_options(source, None, true)?;
    Ok((ir, vm))
}

pub fn compile_luau_to_vm_with_seed(
    source: &str,
    seed: Option<u64>,
) -> Result<(IrModule, String, EmitStats), String> {
    compile_luau_with_options(source, seed, true)
}

pub fn compile_luau_with_options(
    source: &str,
    seed: Option<u64>,
    minify: bool,
) -> Result<(IrModule, String, EmitStats), String> {
    compile_luau_with_full_options(source, seed, minify, None)
}

pub fn compile_luau_with_full_options(
    source: &str,
    seed: Option<u64>,
    minify: bool,
    names: Option<Vec<String>>,
) -> Result<(IrModule, String, EmitStats), String> {
    let effective_seed = seed.unwrap_or_else(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0xA5A5_5A5A_F0F0_0F0F);
        nanos.wrapping_mul(0xBF58_476D_1CE4_E5B9)
            ^ (std::process::id() as u64).rotate_left(23)
            ^ (source.len() as u64)
    });

    let ast = parse_luau(source).map_err(|e| e.to_string())?;
    let mut ir = lower_ast(&ast).map_err(|e| e.to_string())?;
    obfuscate_ir(&mut ir, effective_seed);

    let (vm_code, stats) = emit_luau_vm_with_options(
        &ir,
        EmitOptions {
            seed: Some(effective_seed),
            minify,
            names,
        },
    );
    Ok((ir, vm_code, stats))
}

/// Parses a seed-word document into a word list. Words may be separated by commas,
/// whitespace, or newlines. Lines beginning with `#` are treated as comments and ignored.
pub fn parse_name_seed_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        for token in line.split([',', ' ', '\t', ';']) {
            let t = token.trim();
            if !t.is_empty() {
                words.push(t.to_string());
            }
        }
    }
    words
}

pub fn find_luau_binary(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Some(p.to_path_buf());
        }
    }
    if let Ok(env_p) = std::env::var("LUAU_PATH") {
        let pb = PathBuf::from(env_p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    if let Ok(output) = std::process::Command::new("where.exe").arg("luau").output() {
        if output.status.success() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                if let Some(first) = s.lines().next() {
                    let pb = PathBuf::from(first.trim());
                    if pb.is_file() {
                        return Some(pb);
                    }
                }
            }
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        let candidates = [
            r"Downloads\deob_work\official_luau\0.745\luau.exe",
            r"OneDrive\Documents\wabisabi-vm\tools\vendor\luau-0.745\luau.exe",
            r"Downloads\luau-windows\luau.exe",
            r".rokit\bin\luau.exe",
            r".aftman\bin\luau.exe",
        ];
        for rel in candidates {
            let pb = PathBuf::from(&profile).join(rel);
            if pb.is_file() {
                return Some(pb);
            }
        }
    }
    None
}
