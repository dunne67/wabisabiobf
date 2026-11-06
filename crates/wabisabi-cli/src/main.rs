use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use wabisabi_cli::{compile_luau_with_full_options, find_luau_binary, parse_name_seed_words};

fn print_usage() {
    eprintln!(
        "Wabi Sabi — Luau VM Obfuscator (Phase 3)\n\n\
         Usage:\n  \
           wabisabi [compile] <input.luau> [-o <output.luau>] [--seed <u64>] [--names <words.txt>] [--no-names] [--no-minify] [--dump-ir]\n  \
           wabisabi run <input.luau> [--seed <u64>] [--no-minify] [--luau <path/to/luau.exe>] [-- <program-args>...]"
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_usage();
        return;
    }

    let mut idx = 0;
    let mode = match args[0].as_str() {
        "compile" => {
            idx += 1;
            "compile"
        }
        "run" => {
            idx += 1;
            "run"
        }
        _ => "compile",
    };

    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut luau_bin: Option<PathBuf> = None;
    let mut seed: Option<u64> = None;
    let mut minify = true;
    let mut dump_ir = false;
    let mut names_path: Option<PathBuf> = None;
    let mut disable_names = false;
    let mut prog_args: Vec<String> = Vec::new();

    while idx < args.len() {
        match args[idx].as_str() {
            "-o" | "--output" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Error: expected path after -o");
                    process::exit(1);
                }
                output = Some(PathBuf::from(&args[idx]));
            }
            "--seed" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Error: expected u64 after --seed");
                    process::exit(1);
                }
                seed = match args[idx].parse::<u64>() {
                    Ok(s) => Some(s),
                    Err(_) => {
                        eprintln!("Error: invalid --seed '{}'", args[idx]);
                        process::exit(1);
                    }
                };
            }
            "--no-minify" => {
                minify = false;
            }
            "--names" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Error: expected path after --names");
                    process::exit(1);
                }
                names_path = Some(PathBuf::from(&args[idx]));
            }
            "--no-names" => {
                disable_names = true;
            }
            "--luau" => {
                idx += 1;
                if idx >= args.len() {
                    eprintln!("Error: expected path after --luau");
                    process::exit(1);
                }
                luau_bin = Some(PathBuf::from(&args[idx]));
            }
            "--dump-ir" => {
                dump_ir = true;
            }
            "--" => {
                prog_args.extend_from_slice(&args[idx + 1..]);
                break;
            }
            other if other.starts_with('-') => {
                eprintln!("Error: unknown flag '{other}'");
                print_usage();
                process::exit(1);
            }
            path_str => {
                if input.is_none() {
                    input = Some(PathBuf::from(path_str));
                } else {
                    eprintln!("Error: unexpected positional argument '{path_str}'");
                    process::exit(1);
                }
            }
        }
        idx += 1;
    }

    let Some(input_path) = input else {
        eprintln!("Error: missing <input.luau>");
        print_usage();
        process::exit(1);
    };

    let src = match fs::read_to_string(&input_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error reading {}: {e}", input_path.display());
            process::exit(1);
        }
    };

    // Resolve the seed-word document: explicit --names wins; otherwise auto-detect
    // `names.txt` next to the input, then in the current working directory.
    let resolved_names_path = if disable_names {
        None
    } else {
        names_path.clone().or_else(|| {
        let beside = input_path.with_file_name("names.txt");
        if beside.is_file() {
            return Some(beside);
        }
        let cwd = PathBuf::from("names.txt");
        if cwd.is_file() {
            return Some(cwd);
        }
        None
        })
    };

    let names: Option<Vec<String>> = match &resolved_names_path {
        Some(p) => match fs::read_to_string(p) {
            Ok(text) => {
                let words = parse_name_seed_words(&text);
                if words.is_empty() {
                    eprintln!("Warning: {} has no usable words; using default names", p.display());
                    None
                } else {
                    eprintln!("Using {} seed word(s) from {}", words.len(), p.display());
                    Some(words)
                }
            }
            Err(e) => {
                eprintln!("Error reading names file {}: {e}", p.display());
                process::exit(1);
            }
        },
        None => None,
    };

    let (ir, vm_code, stats) = match compile_luau_with_full_options(&src, seed, minify, names) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("{e}");
            process::exit(1);
        }
    };

    if dump_ir {
        eprintln!("{ir}");
    }

    if mode == "compile" {
        let out_path = output.unwrap_or_else(|| {
            let mut p = input_path.clone();
            p.set_extension("ws.luau");
            p
        });
        if let Err(e) = fs::write(&out_path, &vm_code) {
            eprintln!("Error writing {}: {e}", out_path.display());
            process::exit(1);
        }
        println!(
            "Compiled {} -> {} ({} protos, {} vops [{} superops], {} payload bytes, {} total chars)",
            input_path.display(),
            out_path.display(),
            ir.protos.len(),
            stats.total_vops,
            stats.superop_count,
            stats.payload_bytes,
            vm_code.len()
        );
    } else {
        let Some(luau) = find_luau_binary(luau_bin.as_deref()) else {
            eprintln!("Error: could not locate luau.exe; pass --luau <path> or set LUAU_PATH");
            process::exit(1);
        };
        let tmp_file = env::temp_dir().join(format!("wabisabi_run_{}.luau", process::id()));
        if let Err(e) = fs::write(&tmp_file, &vm_code) {
            eprintln!("Error writing temp file: {e}");
            process::exit(1);
        }
        let mut cmd = Command::new(&luau);
        cmd.arg(&tmp_file);
        if !prog_args.is_empty() {
            cmd.arg("-a").args(&prog_args);
        }
        let status = cmd.status();
        let _ = fs::remove_file(&tmp_file);
        match status {
            Ok(s) => process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("Failed to execute {}: {e}", luau.display());
                process::exit(1);
            }
        }
    }
}
