use std::{
    collections::hash_map::DefaultHasher,
    env,
    fmt::Display,
    fs,
    hash::{Hash, Hasher},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output}
};

use semver::{Version, VersionReq};
use sha3::{Digest, Keccak256};

const REMAPPINGS_FILE: &str = "remappings.txt";
const FOUNDRY_FILE: &str = "foundry.toml";
const SOL_EXT: &str = "sol";
const EXCLUDE_DIRS: [&str; 2] = ["out", "cache"];
const FORGE_CMD: &str = "forge";
const FORGE_BUILD_ARGS: &[&str] = &["build"];
const FORGE_FMT_ARGS: &[&str] = &["fmt", "--check"];
const SLITHER_CMD: &str = "slither";
const SLITHER_ARGS: &[&str] = &[".", "--compile-force-framework", "foundry", "--fail-medium"];
const MIN_FORGE_REQ: &str = ">=1.0.0";
const CONTRACT_ARTIFACT: &str = "GateLock";

fn main() {
    eprintln!("Running build script");
    if let Err(err) = run() {
        panic!("{err}");
    }
}

fn run() -> Result<(), String> {
    let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract_path = manifest_path.join("contracts");

    ensure_contract_exists(&contract_path)?;
    ensure_forge_ready()?;
    log_foundry_config_hash(&contract_path)?;
    log_remappings_hash(&contract_path)?;
    eprintln!("tracking contract sources in {}", contract_path.display());
    track_contract_changes(&contract_path)?;
    run_forge_fmt(&contract_path)?;
    run_forge_build(&contract_path)?;
    log_contract_bytecode_hash(&contract_path)?;
    generate_bindings(&contract_path)?;
    run_slither_analysis(&contract_path)?;

    Ok(())
}

fn ensure_contract_exists(contract_path: &Path) -> Result<(), String> {
    if !contract_path.exists() {
        return Err(format!("Smart contract dir not found at {}", contract_path.display()));
    }
    Ok(())
}

fn ensure_forge_ready() -> Result<(), String> {
    let output = Command::new(FORGE_CMD)
        .arg("--version")
        .output()
        .map_err(|err| format!("failed to execute `{FORGE_CMD} --version`: {err}"))?;

    if !output.status.success() {
        return Err(command_failure(&format!("{FORGE_CMD} --version"), &output));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let version = parse_forge_version(&stdout)
        .ok_or_else(|| format!("unable to parse forge version from `{stdout}`"))?;

    let req = VersionReq::parse(MIN_FORGE_REQ)
        .map_err(|err| format!("invalid version requirement `{MIN_FORGE_REQ}`: {err}"))?;

    if !req.matches(&version) {
        return Err(format!("forge {version} does not satisfy requirement {req}"));
    }

    eprintln!("using forge {version}");

    Ok(())
}

fn parse_forge_version(stdout: &str) -> Option<Version> {
    stdout.split_whitespace().find_map(|part| {
        let candidate = part.trim_start_matches(['v', 'V']);
        if candidate.chars().next()?.is_ascii_digit() {
            Version::parse(candidate)
                .ok()
                .map(|ver| Version::new(ver.major, ver.minor, ver.patch))
        } else {
            None
        }
    })
}

fn log_foundry_config_hash(contract_path: &Path) -> Result<(), String> {
    let config_path = contract_path.join(FOUNDRY_FILE);
    let contents = fs::read_to_string(&config_path)
        .map_err(|err| format!("failed to read file {}: {err}", config_path.display()))?;

    let mut hasher = DefaultHasher::new();
    contents.hash(&mut hasher);
    eprintln!("foundry-config-hash=0x{:016x} ({})", hasher.finish(), config_path.display());
    Ok(())
}

fn log_remappings_hash(contract_path: &Path) -> Result<(), String> {
    let remappings_path = contract_path.join(REMAPPINGS_FILE);
    let contents = fs::read_to_string(&remappings_path)
        .map_err(|err| format!("failed to read remappings {}: {err}", remappings_path.display()))?;
    if contents.trim().is_empty() {
        return Err(format!(
            "remappings file {} is empty; pin dependencies explicitly",
            remappings_path.display()
        ));
    }

    let mut hasher = DefaultHasher::new();
    contents.hash(&mut hasher);
    eprintln!("remappings-hash=0x{:016x} ({})", hasher.finish(), remappings_path.display());
    Ok(())
}

fn run_forge_build(contract_path: &Path) -> Result<(), String> {
    eprintln!(
        "running `{FORGE_CMD} {}` in {}",
        FORGE_BUILD_ARGS.join(" "),
        contract_path.display()
    );
    let output = Command::new(FORGE_CMD)
        .current_dir(contract_path)
        .args(FORGE_BUILD_ARGS)
        .output()
        .map_err(|err| format!("failed to execute `{FORGE_CMD} build`: {err}"))?;

    if !output.status.success() {
        return Err(command_failure(&format!("{FORGE_CMD} build"), &output));
    }

    Ok(())
}

fn run_forge_fmt(contract_path: &Path) -> Result<(), String> {
    eprintln!("running `{FORGE_CMD} {}` in {}", FORGE_FMT_ARGS.join(" "), contract_path.display());
    let output = Command::new(FORGE_CMD)
        .current_dir(contract_path)
        .args(FORGE_FMT_ARGS)
        .output()
        .map_err(|err| format!("failed to execute `{FORGE_CMD} fmt`: {err}"))?;

    if !output.status.success() {
        return Err(command_failure(&format!("{FORGE_CMD} {}", FORGE_FMT_ARGS.join(" ")), &output));
    }

    Ok(())
}

fn track_contract_changes(path: &PathBuf) -> Result<(), String> {
    let entries =
        fs::read_dir(path).map_err(|err| format!("Failed to read dir {path:?}: {err}"))?;
    for entry in entries {
        let path = entry
            .map_err(|err| format!("Failed to process dir entry: {err}"))?
            .path();

        if path.is_dir() {
            let name = path.file_name().unwrap_or_default();
            let name_lossy = name.to_string_lossy();
            if should_skip_dir(&name_lossy) {
                continue;
            }
            track_contract_changes(&path)?;
            continue;
        }

        if path.is_file() {
            let name = path.file_name().unwrap_or_default();
            let name_lossy = name.to_string_lossy();
            let ext = path.extension().unwrap_or_default();
            let is_sol = ext.eq_ignore_ascii_case(SOL_EXT);
            let is_env = name_lossy.contains(".env");
            let should_mark =
                is_sol || name_lossy == FOUNDRY_FILE || name_lossy == REMAPPINGS_FILE || is_env;
            if should_mark {
                mark_for_rerun(path.display());
            }
        }
    }
    Ok(())
}

fn should_skip_dir(name: &str) -> bool {
    if name.starts_with('.') {
        return true;
    }
    EXCLUDE_DIRS.iter().any(|dir| name == *dir)
}

fn mark_for_rerun<T: Display>(name: T) {
    println!("cargo:rerun-if-changed={name}");
}

fn command_failure(cmd: &str, output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!(
        "`{cmd}` failed (status: {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
        output.status.code()
    )
}

fn log_contract_bytecode_hash(contract_path: &Path) -> Result<(), String> {
    let artifact_path = contract_path
        .join("out")
        .join(format!("{CONTRACT_ARTIFACT}.sol"))
        .join(format!("{CONTRACT_ARTIFACT}.json"));
    let raw = fs::read_to_string(&artifact_path)
        .map_err(|err| format!("failed to read {}: {err}", artifact_path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| format!("failed to parse {}: {err}", artifact_path.display()))?;
    let hex_bytecode = json
        .get("bytecode")
        .and_then(|b| b.get("object"))
        .and_then(|obj| obj.as_str())
        .ok_or_else(|| format!("missing bytecode.object in {}", artifact_path.display()))?;
    let normalized = hex_bytecode.trim_start_matches("0x");
    let bytecode = hex::decode(normalized).map_err(|err| {
        format!("failed to decode bytecode from {}: {err}", artifact_path.display())
    })?;
    let mut hasher = Keccak256::new();
    hasher.update(bytecode);
    let hash = hasher.finalize();
    println!("cargo:warning=GateLock bytecode keccak256=0x{}", hex::encode(hash));
    Ok(())
}

fn run_slither_analysis(contract_path: &Path) -> Result<(), String> {
    eprintln!("running `{SLITHER_CMD} {}` in {}", SLITHER_ARGS.join(" "), contract_path.display());

    let output = Command::new(SLITHER_CMD)
        .current_dir(contract_path)
        .args(SLITHER_ARGS)
        .output()
        .map_err(|err| format!("failed to execute `{SLITHER_CMD}`: {err}"))?;

    if !output.status.success() {
        return Err(command_failure(&format!("{SLITHER_CMD} {}", SLITHER_ARGS.join(" ")), &output));
    }

    Ok(())
}

fn generate_bindings(contract_path: &Path) -> Result<(), String> {
    let out_dir = env::var("OUT_DIR").map_err(|e| format!("Could not get OUT_DIR: {e}"))?;
    let bindings_path = PathBuf::from(&out_dir).join("bindings.rs");

    let json_path = contract_path
        .join("out")
        .join(format!("{CONTRACT_ARTIFACT}.sol"))
        .join(format!("{CONTRACT_ARTIFACT}.json"));

    let json_path_str = json_path.to_string_lossy();

    // Ensure the JSON file exists, as the bindings.rs points to it
    if !json_path.exists() {
        return Err(format!("Contract artifact not found at {}", json_path.display()));
    }

    let content = format!(
        r#"#[rustfmt::skip]
pub mod gate_lock {{
    alloy::sol!(
        #[allow(missing_docs)]
        #[sol(rpc, abi)]
        #[derive(Debug, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
        GateLock,
        "{}"
    );
}}
"#,
        json_path_str
    );

    let mut file = fs::File::create(&bindings_path)
        .map_err(|e| format!("could not create bindings at {}: {e}", bindings_path.display()))?;

    file.write_all(content.as_bytes())
        .map_err(|e| format!("could not write bindings to {}: {e}", bindings_path.display()))?;

    eprintln!("Generated bindings at {}", bindings_path.display());

    Ok(())
}
