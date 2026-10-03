use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use clap::{Args, CommandFactory, Parser, Subcommand};

use layersift::analysis::{Analysis, Options, analyze, caesar, xor};
use layersift::hashing::{digest, digest_candidates, explain_hash};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_ANALYSIS_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Parser)]
#[command(
    version,
    about = "Inspect encoded layers and recover embedded files offline"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Find encoded fields, transformation layers and embedded files.
    Inspect {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        options: AnalyzeArgs,
        #[arg(long)]
        json: bool,
    },
    /// Write recovered files into a chosen local directory.
    Extract {
        #[command(flatten)]
        input: Input,
        #[command(flatten)]
        options: AnalyzeArgs,
        #[arg(long)]
        out: PathBuf,
    },
    /// Base64 or hex conversion.
    Codec {
        #[command(subcommand)]
        operation: CodecCommand,
    },
    /// Apply a reversible basic cipher.
    Cipher {
        #[command(subcommand)]
        operation: CipherCommand,
    },
    /// Create, verify or identify a digest.
    Hash {
        #[command(subcommand)]
        operation: HashCommand,
    },
}

#[derive(Args)]
struct Input {
    #[arg(long, conflicts_with = "file")]
    text: Option<String>,
    #[arg(long, conflicts_with = "text")]
    file: Option<PathBuf>,
}

impl Input {
    fn read(&self) -> Result<(String, Vec<u8>)> {
        match (&self.text, &self.file) {
            (Some(text), None) => Ok(("text".into(), text.as_bytes().to_vec())),
            (None, Some(path)) => Ok((path.display().to_string(), fs::read(path)?)),
            _ => Err("provide exactly one of --text or --file".into()),
        }
    }

    fn read_for_analysis(&self) -> Result<(String, Vec<u8>)> {
        match (&self.text, &self.file) {
            (Some(text), None) if text.len() as u64 > MAX_ANALYSIS_BYTES => {
                Err("input exceeds the 16 MiB analysis limit".into())
            }
            (None, Some(path)) => Ok((path.display().to_string(), read_analysis_file(path)?)),
            _ => self.read(),
        }
    }
}

fn read_analysis_file(path: &Path) -> Result<Vec<u8>> {
    if fs::metadata(path)?.len() > MAX_ANALYSIS_BYTES {
        return Err("file exceeds the 16 MiB analysis limit".into());
    }
    let data = fs::read(path)?;
    if data.len() as u64 > MAX_ANALYSIS_BYTES {
        return Err("file exceeds the 16 MiB analysis limit".into());
    }
    Ok(data)
}

#[derive(Args)]
struct AnalyzeArgs {
    /// XOR key as UTF-8 text.
    #[arg(long, conflicts_with = "xor_key_hex")]
    xor_key: Option<String>,
    /// XOR key as hex bytes.
    #[arg(long, conflicts_with = "xor_key")]
    xor_key_hex: Option<String>,
    /// Caesar shift to undo, for example 3 rotates by -3.
    #[arg(long)]
    caesar: Option<i32>,
    /// Try single-byte XOR keys against known file headers.
    #[arg(long)]
    auto_xor: bool,
    #[arg(long)]
    zip_password: Option<String>,
    #[arg(long, default_value_t = 4)]
    depth: usize,
}

impl AnalyzeArgs {
    fn options(&self) -> Result<Options> {
        let key = match (&self.xor_key, &self.xor_key_hex) {
            (Some(text), None) => Some(text.as_bytes().to_vec()),
            (None, Some(value)) => Some(hex::decode(value)?),
            _ => None,
        };
        if key.as_ref().is_some_and(Vec::is_empty) {
            return Err("XOR key cannot be empty".into());
        }
        Ok(Options {
            xor_key: key,
            caesar_shift: self.caesar,
            auto_xor: self.auto_xor,
            zip_password: self
                .zip_password
                .as_ref()
                .map(|value| value.as_bytes().to_vec()),
            depth: self.depth,
        })
    }
}

#[derive(Subcommand)]
enum CodecCommand {
    Encode {
        #[arg(value_parser = ["base64", "hex"])]
        format: String,
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Decode {
        #[arg(value_parser = ["base64", "hex"])]
        format: String,
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum CipherCommand {
    Caesar {
        #[command(flatten)]
        input: Input,
        #[arg(long)]
        shift: i32,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    Xor {
        #[command(flatten)]
        input: Input,
        #[arg(long, conflicts_with = "key_hex")]
        key: Option<String>,
        #[arg(long, conflicts_with = "key")]
        key_hex: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum HashCommand {
    Make {
        algorithm: String,
        #[command(flatten)]
        input: Input,
    },
    Verify {
        algorithm: String,
        digest: String,
        #[command(flatten)]
        input: Input,
    },
    Identify {
        digest: String,
    },
    Explain {
        algorithm: String,
    },
}

fn output(bytes: &[u8], path: Option<&Path>) -> Result<()> {
    if let Some(path) = path {
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        eprintln!("wrote {} bytes to {}", bytes.len(), path.display());
    } else {
        io::stdout().lock().write_all(bytes)?;
    }
    Ok(())
}

fn print_analysis(report: &Analysis) {
    println!(
        "{} candidates examined; {} field matches; {} artifacts found",
        report.visited,
        report.matches.len(),
        report.artifacts.len()
    );
    for matched in &report.matches {
        println!(
            "  field: {} ({})",
            matched["origin"].as_str().unwrap_or("unknown"),
            matched["field_type"].as_str().unwrap_or("text")
        );
        if let Some(candidates) = matched["hash_candidates"].as_array()
            && !candidates.is_empty()
        {
            let names = candidates
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            println!("    possible hash formats: {names}");
        }
    }
    for item in &report.artifacts {
        let summary = item.summary();
        println!(
            "- {} ({} bytes, {}): {}",
            item.filename,
            item.data.len(),
            summary["content_hint"].as_str().unwrap_or("unknown"),
            item.steps.join(" -> ")
        );
        println!("  source: {}", item.origin);
    }
    for note in &report.notes {
        eprintln!("note: {note}");
    }
}

fn write_extracted(report: &Analysis, out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    if out.join("report.json").exists() {
        return Err("report.json already exists in the output directory".into());
    }
    let mut manifest = Vec::new();
    for (index, item) in report.artifacts.iter().enumerate() {
        let basename: String = item
            .filename
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || ".-_".contains(character) {
                    character
                } else {
                    '_'
                }
            })
            .take(80)
            .collect();
        let target = out.join(format!("{:04}_{}", index + 1, basename));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)?;
        file.write_all(&item.data)?;
        println!("{}", target.display());
        let mut record = item.summary();
        record["saved_as"] = serde_json::Value::String(target.display().to_string());
        manifest.push(record);
    }
    let manifest_path = out.join("report.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)?;
    let mut summary = report.summary();
    summary["artifacts"] = serde_json::Value::Array(manifest);
    file.write_all(serde_json::to_string_pretty(&summary)?.as_bytes())?;
    println!("report: {}", manifest_path.display());
    Ok(())
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(answer.trim().to_string())
}

fn interactive() -> Result<()> {
    println!("LayerSift — inspect and recover content offline\n");
    loop {
        println!("1  Inspect text");
        println!("2  Inspect a file");
        println!("3  Extract from a file");
        println!("4  Encode text as Base64");
        println!("5  Hash text");
        println!("h  Show all commands");
        println!("q  Quit");
        let choice = prompt("\nChoose an action: ")?;
        let action = || -> Result<bool> {
            match choice.as_str() {
                "1" => {
                    let text = prompt("Text: ")?;
                    if !text.is_empty() {
                        let report = analyze(
                            text.as_bytes(),
                            "Text input",
                            &Options {
                                depth: 4,
                                auto_xor: true,
                                ..Options::default()
                            },
                        )?;
                        print_analysis(&report);
                    }
                }
                "2" | "3" => {
                    let path = prompt("File path: ")?;
                    if !path.is_empty() {
                        let path = PathBuf::from(path.trim_matches('"').replace("\\ ", " "));
                        let data = read_analysis_file(&path)?;
                        let report = analyze(
                            &data,
                            &path.display().to_string(),
                            &Options {
                                depth: 4,
                                auto_xor: true,
                                ..Options::default()
                            },
                        )?;
                        print_analysis(&report);
                        if choice == "3" {
                            let out = prompt("Output folder: ")?;
                            if !out.is_empty() {
                                write_extracted(&report, Path::new(&out))?;
                            }
                        }
                    }
                }
                "4" => {
                    let text = prompt("Text: ")?;
                    println!("{}", STANDARD.encode(text.as_bytes()));
                }
                "5" => {
                    let algorithm = prompt("Algorithm [sha256]: ")?;
                    let text = prompt("Text: ")?;
                    println!(
                        "{}",
                        digest(
                            if algorithm.is_empty() {
                                "sha256"
                            } else {
                                &algorithm
                            },
                            text.as_bytes()
                        )?
                    );
                }
                "h" | "help" => {
                    Cli::command().print_help()?;
                    println!("\n");
                }
                "q" | "quit" | "exit" | "" => return Ok(false),
                _ => println!("Choose 1–5, h, or q."),
            }
            Ok(true)
        };
        match action() {
            Ok(false) => break,
            Ok(true) => println!(),
            Err(error) => eprintln!("error: {error}\n"),
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    if std::env::args_os().len() == 1 {
        if io::stdin().is_terminal() {
            return interactive();
        }
        Cli::command().print_help()?;
        println!("\n\nExamples: layersift inspect --text 'aGVsbG8=' | layersift --help");
        return Ok(());
    }
    match Cli::parse().command {
        Command::Inspect {
            input,
            options,
            json,
        } => {
            let (label, bytes) = input.read_for_analysis()?;
            let report = analyze(&bytes, &label, &options.options()?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report.summary())?);
            } else {
                print_analysis(&report);
            }
        }
        Command::Extract {
            input,
            options,
            out,
        } => {
            let (label, bytes) = input.read_for_analysis()?;
            let report = analyze(&bytes, &label, &options.options()?)?;
            write_extracted(&report, &out)?;
        }
        Command::Codec { operation } => match operation {
            CodecCommand::Encode { format, input, out } => {
                let (_, bytes) = input.read()?;
                let encoded = if format == "base64" {
                    STANDARD.encode(bytes)
                } else {
                    hex::encode(bytes)
                };
                output(encoded.as_bytes(), out.as_deref())?;
            }
            CodecCommand::Decode { format, input, out } => {
                let (_, bytes) = input.read()?;
                let compact: Vec<u8> = bytes
                    .into_iter()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                let decoded = if format == "base64" {
                    STANDARD.decode(compact)?
                } else {
                    hex::decode(compact)?
                };
                output(&decoded, out.as_deref())?;
            }
        },
        Command::Cipher { operation } => match operation {
            CipherCommand::Caesar { input, shift, out } => {
                let (_, bytes) = input.read()?;
                output(&caesar(&bytes, shift), out.as_deref())?;
            }
            CipherCommand::Xor {
                input,
                key,
                key_hex,
                out,
            } => {
                let (_, bytes) = input.read()?;
                let key = match (key, key_hex) {
                    (Some(value), None) => value.into_bytes(),
                    (None, Some(value)) => hex::decode(value)?,
                    _ => return Err("provide --key or --key-hex".into()),
                };
                output(&xor(&bytes, &key)?, out.as_deref())?;
            }
        },
        Command::Hash { operation } => match operation {
            HashCommand::Make { algorithm, input } => {
                let (_, bytes) = input.read()?;
                println!("{}", digest(&algorithm, &bytes)?);
            }
            HashCommand::Verify {
                algorithm,
                digest: expected,
                input,
            } => {
                let (_, bytes) = input.read()?;
                let actual = digest(&algorithm, &bytes)?;
                if actual.eq_ignore_ascii_case(&expected) {
                    println!("match");
                } else {
                    println!("no match");
                    std::process::exit(1);
                }
            }
            HashCommand::Identify { digest } => {
                let kinds = digest_candidates(&digest);
                if kinds.is_empty() {
                    println!("No supported hexadecimal shape recognized");
                } else {
                    println!(
                        "Possible formats (shape alone is not proof): {}",
                        kinds.join(", ")
                    );
                }
            }
            HashCommand::Explain { algorithm } => println!("{}", explain_hash(&algorithm)?),
        },
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
