use std::collections::{HashSet, VecDeque};
use std::error::Error;
use std::io::{Cursor, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::{GzDecoder, ZlibDecoder};
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zip::ZipArchive;

use crate::hashing::digest_candidates;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const MAX_INPUT: usize = 16 * 1024 * 1024;
const MAX_EXPANDED: usize = 32 * 1024 * 1024;
const MAX_CANDIDATES: usize = 256;
const MAX_ARTIFACTS: usize = 256;
const MAX_DEPTH: usize = 4;

#[derive(Default)]
pub struct Options {
    pub xor_key: Option<Vec<u8>>,
    pub caesar_shift: Option<i32>,
    pub auto_xor: bool,
    pub zip_password: Option<Vec<u8>>,
    pub depth: usize,
}

struct Candidate {
    origin: String,
    steps: Vec<String>,
    data: Vec<u8>,
}

pub struct Artifact {
    pub kind: String,
    pub filename: String,
    pub origin: String,
    pub steps: Vec<String>,
    pub data: Vec<u8>,
}

impl Artifact {
    pub fn summary(&self) -> Value {
        let hint = content_hint(&self.data);
        let binary = !readable_text(&self.data)
            || matches!(
                hint,
                "PNG image" | "JPEG image" | "PDF document" | "ZIP archive"
            );
        let hex_preview = binary.then(|| {
            self.data
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        });
        json!({
            "kind": self.kind,
            "content_hint": hint,
            "preview": (!binary).then(|| std::str::from_utf8(&self.data).ok()).flatten().map(|text| text.chars().take(180).collect::<String>()),
            "hex_preview": hex_preview,
            "filename": self.filename,
            "origin": self.origin,
            "steps": self.steps,
            "bytes": self.data.len(),
            "sha256": hex::encode(Sha256::digest(&self.data))
        })
    }
}

fn content_hint(data: &[u8]) -> &'static str {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return "PNG image";
    }
    if data.starts_with(b"\xff\xd8\xff") {
        return "JPEG image";
    }
    if data.starts_with(b"%PDF-") {
        return "PDF document";
    }
    if data.starts_with(b"PK\x03\x04") {
        return "ZIP archive";
    }
    if let Ok(text) = std::str::from_utf8(data) {
        let trimmed = text.trim();
        if serde_json::from_str::<Value>(trimmed).is_ok() {
            return "JSON";
        }
        if trimmed.contains('@') && !trimmed.contains('\n') && trimmed.split('@').count() == 2 {
            return "possible email address";
        }
        if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
            return "URL";
        }
        if readable_text(data) {
            return "text";
        }
    }
    "binary data"
}

pub struct Analysis {
    pub visited: usize,
    pub matches: Vec<Value>,
    pub artifacts: Vec<Artifact>,
    pub notes: Vec<String>,
}

impl Analysis {
    pub fn summary(&self) -> Value {
        json!({
            "visited_candidates": self.visited,
            "matches": self.matches,
            "artifacts": self.artifacts.iter().map(Artifact::summary).collect::<Vec<_>>(),
            "notes": self.notes
        })
    }
}

fn observation(source: &Candidate) -> Value {
    let hash_candidates = std::str::from_utf8(&source.data)
        .ok()
        .map(|text| digest_candidates(text.trim()))
        .unwrap_or_default();
    json!({
        "origin": source.origin,
        "field_type": source.steps.last(),
        "bytes": source.data.len(),
        "hash_candidates": hash_candidates
    })
}

pub fn caesar(data: &[u8], shift: i32) -> Vec<u8> {
    let shift = shift.rem_euclid(26) as u8;
    data.iter()
        .map(|value| {
            if value.is_ascii_uppercase() {
                b'A' + (value - b'A' + shift) % 26
            } else if value.is_ascii_lowercase() {
                b'a' + (value - b'a' + shift) % 26
            } else {
                *value
            }
        })
        .collect()
}

pub fn xor(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() {
        return Err("XOR key cannot be empty".into());
    }
    Ok(data
        .iter()
        .enumerate()
        .map(|(index, value)| value ^ key[index % key.len()])
        .collect())
}

fn text_sources(data: &[u8], label: &str) -> Vec<Candidate> {
    let Ok(text) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    if text.trim_start().starts_with(['{', '['])
        && let Ok(document) = serde_json::from_str::<Value>(text)
    {
        fn visit(value: &Value, path: String, found: &mut Vec<Candidate>, level: usize) {
            if level > 32 || found.len() >= MAX_CANDIDATES {
                return;
            }
            match value {
                Value::String(text) if text.len() >= 8 => found.push(Candidate {
                    origin: path,
                    steps: vec!["JSON string".into()],
                    data: text.as_bytes().to_vec(),
                }),
                Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        visit(item, format!("{path}[{index}]"), found, level + 1);
                    }
                }
                Value::Object(items) => {
                    for (key, item) in items {
                        visit(item, format!("{path}.{key}"), found, level + 1);
                    }
                }
                _ => {}
            }
        }
        visit(&document, "$".into(), &mut found, 0);
    }

    let sql = Regex::new(r"'(?:''|[^'])*'").expect("static regex");
    for matched in sql.find_iter(text).take(MAX_CANDIDATES) {
        let value = matched.as_str()[1..matched.len() - 1].replace("''", "'");
        if value.len() >= 8 {
            found.push(Candidate {
                origin: format!("{label}:sql@{}", matched.start()),
                steps: vec!["SQL string".into()],
                data: value.into_bytes(),
            });
        }
    }
    let b64 = Regex::new(r"(?-u:[A-Za-z0-9+/]{20,}={0,2})").expect("static regex");
    for matched in b64.find_iter(text).take(MAX_CANDIDATES) {
        let token = matched.as_str();
        if token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        found.push(Candidate {
            origin: format!("{label}:base64@{}", matched.start()),
            steps: vec!["text token".into()],
            data: token.as_bytes().to_vec(),
        });
    }
    let hex = Regex::new(r"(?-u:[0-9A-Fa-f]{24,})").expect("static regex");
    for matched in hex.find_iter(text).take(MAX_CANDIDATES) {
        found.push(Candidate {
            origin: format!("{label}:hex@{}", matched.start()),
            steps: vec!["text token".into()],
            data: matched.as_str().as_bytes().to_vec(),
        });
    }
    found.truncate(MAX_CANDIDATES);
    found
}

fn decoded_layers(data: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut result = Vec::new();
    let compact: Vec<u8> = data
        .iter()
        .copied()
        .filter(|value| !value.is_ascii_whitespace())
        .collect();
    let hex_only = compact.iter().all(u8::is_ascii_hexdigit);
    if !hex_only
        && compact.len() >= 8
        && compact.len().is_multiple_of(4)
        && compact
            .iter()
            .all(|value| value.is_ascii_alphanumeric() || b"+/=".contains(value))
        && let Ok(decoded) = STANDARD.decode(&compact)
        && !decoded.is_empty()
        && decoded != data
        && decoded.len() <= MAX_EXPANDED
        && useful_decoded(&decoded)
    {
        result.push(("base64 decode", decoded));
    }
    if compact.len() >= 8
        && compact.len().is_multiple_of(2)
        && compact.iter().all(u8::is_ascii_hexdigit)
        && let Ok(decoded) = hex::decode(&compact)
        && !decoded.is_empty()
        && decoded != data
        && decoded.len() <= MAX_EXPANDED
        && useful_decoded(&decoded)
    {
        result.push(("hex decode", decoded));
    }
    if data.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        if GzDecoder::new(data)
            .take((MAX_EXPANDED + 1) as u64)
            .read_to_end(&mut decoded)
            .is_ok()
            && !decoded.is_empty()
            && decoded.len() <= MAX_EXPANDED
        {
            result.push(("gzip decompress", decoded));
        }
    }
    if data.starts_with(&[0x78, 0x01])
        || data.starts_with(&[0x78, 0x9c])
        || data.starts_with(&[0x78, 0xda])
    {
        let mut decoded = Vec::new();
        if ZlibDecoder::new(data)
            .take((MAX_EXPANDED + 1) as u64)
            .read_to_end(&mut decoded)
            .is_ok()
            && !decoded.is_empty()
            && decoded.len() <= MAX_EXPANDED
        {
            result.push(("zlib decompress", decoded));
        }
    }
    result
}

fn useful_decoded(data: &[u8]) -> bool {
    if readable_text(data) {
        return true;
    }
    let signatures: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"%PDF-",
        b"PK\x03\x04",
        b"\x1f\x8b",
        b"\x78\x01",
        b"\x78\x9c",
        b"\x78\xda",
    ];
    signatures.iter().any(|signature| {
        data.windows(signature.len())
            .any(|window| window == *signature)
    })
}

fn readable_text(data: &[u8]) -> bool {
    if data.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    let mut total = 0;
    let mut printable = 0;
    for character in text.chars().take(4096) {
        total += 1;
        if !character.is_control() || matches!(character, '\t' | '\n' | '\r') {
            printable += 1;
        }
    }
    total > 0 && printable * 10 >= total * 9
}

fn find_from(data: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    data.get(start..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| start + offset)
}

fn png_end(data: &[u8], start: usize) -> Option<usize> {
    let mut position = start + 8;
    while position + 12 <= data.len() {
        let length = u32::from_be_bytes(data[position..position + 4].try_into().ok()?) as usize;
        if length > MAX_EXPANDED || position + length + 12 > data.len() {
            return None;
        }
        let expected = u32::from_be_bytes(
            data[position + length + 8..position + length + 12]
                .try_into()
                .ok()?,
        );
        let actual = crc32fast::hash(&data[position + 4..position + length + 8]);
        if expected != actual {
            return None;
        }
        let is_end = &data[position + 4..position + 8] == b"IEND";
        position += length + 12;
        if is_end {
            return Some(position);
        }
    }
    None
}

fn carved(candidate: &Candidate) -> Vec<Artifact> {
    let mut artifacts = Vec::new();
    let signatures: &[(&[u8], &str)] = &[
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpg"),
        (b"%PDF-", "pdf"),
    ];
    for &(signature, kind) in signatures {
        let mut offset = 0;
        while let Some(start) = find_from(&candidate.data, signature, offset) {
            offset = start + signature.len();
            let end = match kind {
                "png" => png_end(&candidate.data, start),
                "jpg" => find_from(&candidate.data, b"\xff\xd9", offset).map(|value| value + 2),
                "pdf" => find_from(&candidate.data, b"%%EOF", offset).map(|value| value + 5),
                _ => None,
            };
            if let Some(end) = end {
                if end - start > MAX_EXPANDED {
                    continue;
                }
                let mut steps = candidate.steps.clone();
                steps.push(format!("carve {kind} at byte {start}"));
                artifacts.push(Artifact {
                    kind: kind.into(),
                    filename: format!("carved-{start}.{kind}"),
                    origin: candidate.origin.clone(),
                    steps,
                    data: candidate.data[start..end].to_vec(),
                });
            }
            if artifacts.len() >= MAX_ARTIFACTS {
                break;
            }
        }
    }
    artifacts
}

fn zip_members(
    candidate: &Candidate,
    password: Option<&[u8]>,
    notes: &mut Vec<String>,
) -> Vec<Artifact> {
    if find_from(&candidate.data, b"PK\x03\x04", 0).is_none() {
        return Vec::new();
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(&candidate.data)) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for index in 0..archive.len().min(MAX_ARTIFACTS) {
        let file = if let Some(password) = password {
            archive.by_index_decrypt(index, password)
        } else {
            archive.by_index(index)
        };
        match file {
            Ok(file) => {
                if file.is_dir() || file.size() > MAX_EXPANDED as u64 {
                    continue;
                }
                let name = file.name().to_string();
                let mut content = Vec::new();
                if file
                    .take((MAX_EXPANDED + 1) as u64)
                    .read_to_end(&mut content)
                    .is_err()
                    || content.len() > MAX_EXPANDED
                {
                    notes.push(format!("could not read ZIP member {name}"));
                    continue;
                }
                let filename = name
                    .replace('\\', "/")
                    .rsplit('/')
                    .next()
                    .unwrap_or("member.bin")
                    .to_string();
                let mut steps = candidate.steps.clone();
                steps.push(format!("zip member {name}"));
                result.push(Artifact {
                    kind: "zip member".into(),
                    filename: if filename.is_empty() {
                        "member.bin".into()
                    } else {
                        filename
                    },
                    origin: candidate.origin.clone(),
                    steps,
                    data: content,
                });
            }
            Err(error) => notes.push(format!("ZIP member {index}: {error}")),
        }
    }
    result
}

fn add_artifact(artifacts: &mut Vec<Artifact>, seen: &mut HashSet<[u8; 32]>, artifact: Artifact) {
    if artifacts.len() >= MAX_ARTIFACTS {
        return;
    }
    let fingerprint: [u8; 32] = Sha256::digest(&artifact.data).into();
    if seen.insert(fingerprint) {
        artifacts.push(artifact);
    }
}

fn magic_after_xor(data: &[u8], key: u8) -> bool {
    let signatures: &[&[u8]] = &[
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",
        b"%PDF-",
        b"PK\x03\x04",
        b"\x1f\x8b",
    ];
    signatures.iter().any(|signature| {
        data.windows(signature.len()).take(1024).any(|window| {
            window
                .iter()
                .zip(*signature)
                .all(|(byte, expected)| byte ^ key == *expected)
        })
    })
}

pub fn analyze(data: &[u8], label: &str, options: &Options) -> Result<Analysis> {
    if data.len() > MAX_INPUT {
        return Err(format!("input exceeds {MAX_INPUT} bytes").into());
    }
    if options.depth > MAX_DEPTH {
        return Err(format!("depth must be 0-{MAX_DEPTH}").into());
    }
    let mut queue = VecDeque::new();
    queue.push_back(Candidate {
        origin: label.into(),
        steps: Vec::new(),
        data: data.to_vec(),
    });
    let initial_sources = text_sources(data, label);
    let mut matches: Vec<Value> = initial_sources.iter().map(observation).collect();
    queue.extend(initial_sources);
    if let Some(key) = &options.xor_key {
        queue.push_back(Candidate {
            origin: label.into(),
            steps: vec!["xor with supplied key".into()],
            data: xor(data, key)?,
        });
    }
    if let Some(shift) = options.caesar_shift {
        queue.push_back(Candidate {
            origin: label.into(),
            steps: vec![format!("caesar shift -{shift}")],
            data: caesar(data, -shift),
        });
    }
    if options.auto_xor && data.len() <= 1024 * 1024 {
        for key in 0..=255_u8 {
            if magic_after_xor(data, key) {
                queue.push_back(Candidate {
                    origin: label.into(),
                    steps: vec![format!("single-byte XOR key 0x{key:02x}")],
                    data: xor(data, &[key])?,
                });
            }
        }
    }
    let mut visited = HashSet::new();
    let mut artifact_hashes = HashSet::new();
    let mut artifacts = Vec::new();
    let mut notes = Vec::new();
    while let Some(candidate) = queue.pop_front() {
        if visited.len() >= MAX_CANDIDATES {
            notes.push("candidate limit reached".into());
            break;
        }
        if candidate.data.len() > MAX_EXPANDED {
            continue;
        }
        let fingerprint: [u8; 32] = Sha256::digest(&candidate.data).into();
        if !visited.insert(fingerprint) {
            continue;
        }

        for artifact in carved(&candidate) {
            add_artifact(&mut artifacts, &mut artifact_hashes, artifact);
        }
        for artifact in zip_members(&candidate, options.zip_password.as_deref(), &mut notes) {
            if candidate.steps.len() < options.depth {
                queue.push_back(Candidate {
                    origin: artifact.origin.clone(),
                    steps: artifact.steps.clone(),
                    data: artifact.data.clone(),
                });
            }
            add_artifact(&mut artifacts, &mut artifact_hashes, artifact);
        }
        if candidate.steps.iter().any(|step| {
            step == "base64 decode" || step == "hex decode" || step.ends_with("decompress")
        }) && readable_text(&candidate.data)
        {
            add_artifact(
                &mut artifacts,
                &mut artifact_hashes,
                Artifact {
                    kind: "text".into(),
                    filename: "decoded.txt".into(),
                    origin: candidate.origin.clone(),
                    steps: candidate.steps.clone(),
                    data: candidate.data.clone(),
                },
            );
        } else if candidate.steps.iter().any(|step| {
            step == "base64 decode" || step == "hex decode" || step.ends_with("decompress")
        }) && !candidate.data.is_empty()
        {
            add_artifact(
                &mut artifacts,
                &mut artifact_hashes,
                Artifact {
                    kind: "binary".into(),
                    filename: "decoded.bin".into(),
                    origin: candidate.origin.clone(),
                    steps: candidate.steps.clone(),
                    data: candidate.data.clone(),
                },
            );
        }
        if candidate.steps.len() >= options.depth {
            continue;
        }
        for (step, decoded) in decoded_layers(&candidate.data) {
            let mut steps = candidate.steps.clone();
            steps.push(step.into());
            queue.push_back(Candidate {
                origin: candidate.origin.clone(),
                steps,
                data: decoded,
            });
        }
        if options.auto_xor && candidate.data.len() <= 1024 * 1024 && candidate.steps.len() <= 2 {
            for key in 1..=255_u8 {
                if magic_after_xor(&candidate.data, key) {
                    let mut steps = candidate.steps.clone();
                    steps.push(format!("single-byte XOR key 0x{key:02x}"));
                    queue.push_back(Candidate {
                        origin: candidate.origin.clone(),
                        steps,
                        data: xor(&candidate.data, &[key])?,
                    });
                }
            }
        }
        if candidate.steps.last().is_some_and(|step| {
            step == "base64 decode" || step == "hex decode" || step.ends_with("decompress")
        }) {
            for mut source in text_sources(&candidate.data, &candidate.origin) {
                matches.push(observation(&source));
                let mut steps = candidate.steps.clone();
                steps.append(&mut source.steps);
                source.steps = steps;
                queue.push_back(source);
            }
        }
    }
    Ok(Analysis {
        visited: visited.len(),
        matches,
        artifacts,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> Options {
        Options {
            depth: 4,
            ..Options::default()
        }
    }

    #[test]
    fn binary_artifact_reports_size_and_first_bytes() {
        let artifact = Artifact {
            kind: "binary".into(),
            filename: "sample.bin".into(),
            origin: "fixture".into(),
            steps: vec!["base64 decode".into()],
            data: vec![0x00, 0xFF, 0x89, 0x50],
        };
        let summary = artifact.summary();
        assert_eq!(summary["bytes"], 4);
        assert_eq!(summary["hex_preview"], "00 FF 89 50");
        assert!(summary["preview"].is_null());

        let pdf = Artifact {
            kind: "pdf".into(),
            filename: "sample.pdf".into(),
            origin: "fixture".into(),
            steps: vec!["carve pdf at byte 0".into()],
            data: b"%PDF-1.4\nsample\n%%EOF".to_vec(),
        };
        let summary = pdf.summary();
        assert_eq!(summary["bytes"], 21);
        assert!(
            summary["hex_preview"]
                .as_str()
                .unwrap()
                .starts_with("25 50 44 46")
        );
        assert!(summary["preview"].is_null());
    }

    #[test]
    fn finds_base64_email_in_json_and_sql() {
        let email = STANDARD.encode("user@example.com");
        let json_input = format!(r#"{{"row":{{"email":"{email}"}}}}"#);
        let report = analyze(json_input.as_bytes(), "data.json", &options()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.data == b"user@example.com" && item.origin == "$.row.email")
        );

        let sql_input = format!("INSERT INTO users(email) VALUES ('{email}');");
        let report = analyze(sql_input.as_bytes(), "dump.sql", &options()).unwrap();
        assert!(report.artifacts.iter().any(
            |item| item.data == b"user@example.com" && item.origin.starts_with("dump.sql:sql@")
        ));
    }

    #[test]
    fn identifies_hash_shape_in_json_field_without_claiming_algorithm() {
        let input = format!(r#"{{"digest":"{}"}}"#, "a".repeat(64));
        let report = analyze(input.as_bytes(), "data.json", &options()).unwrap();
        let field = report
            .matches
            .iter()
            .find(|item| item["origin"] == "$.digest")
            .unwrap();
        assert_eq!(field["hash_candidates"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn keeps_utf8_text_after_base64_decoding() {
        let encoded = STANDARD.encode("İçerik: merhaba dünya");
        let report = analyze(encoded.as_bytes(), "text", &options()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.data == "İçerik: merhaba dünya".as_bytes())
        );
    }

    #[test]
    fn reports_every_location_of_repeated_base64_value() {
        let email = STANDARD.encode("user@example.com");
        let input = format!("INSERT INTO users VALUES ('{email}'), ('{email}');");
        let report = analyze(input.as_bytes(), "dump.sql", &options()).unwrap();
        let sql_matches = report
            .matches
            .iter()
            .filter(|item| {
                item["origin"]
                    .as_str()
                    .is_some_and(|origin| origin.starts_with("dump.sql:sql@"))
            })
            .count();
        assert_eq!(sql_matches, 2);
        assert_eq!(
            report
                .artifacts
                .iter()
                .filter(|item| item.data == b"user@example.com")
                .count(),
            1
        );
    }

    #[test]
    fn decodes_caesar_then_base64() {
        let original = STANDARD.encode("hello@example.com");
        let encoded = caesar(original.as_bytes(), 3);
        let report = analyze(
            &encoded,
            "cipher.txt",
            &Options {
                caesar_shift: Some(3),
                depth: 4,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.data == b"hello@example.com")
        );
    }

    #[test]
    fn auto_xor_recovers_file_header() {
        let pdf = b"%PDF-1.4\nsample\n%%EOF";
        let hidden = xor(pdf, &[0x42]).unwrap();
        let report = analyze(
            &hidden,
            "hidden.bin",
            &Options {
                auto_xor: true,
                depth: 4,
                ..Options::default()
            },
        )
        .unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.kind == "pdf" && item.data == pdf)
        );
    }

    #[test]
    fn hex_string_decodes_as_hex_not_base64() {
        let input = "a".repeat(64);
        let report = analyze(input.as_bytes(), "text", &options()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .all(|item| !item.steps.iter().any(|step| step == "base64 decode"))
        );
        assert!(report.artifacts.is_empty());
    }

    #[test]
    fn plain_words_do_not_create_binary_base64_artifacts() {
        let report = analyze(b"local fixture", "text", &options()).unwrap();
        assert!(report.artifacts.is_empty());
    }

    #[test]
    fn base64_json_returns_the_document() {
        let document = r#"{"name":"ada","n":1}"#;
        let encoded = STANDARD.encode(document);
        let report = analyze(encoded.as_bytes(), "text", &options()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.data == document.as_bytes() && item.steps == ["base64 decode"])
        );
    }

    #[test]
    fn extracts_zip_member_from_embedded_archive() {
        use std::io::Write;
        use zip::{ZipWriter, write::SimpleFileOptions};

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("nested/note.txt", SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"inside archive").unwrap();
        let zip = writer.finish().unwrap().into_inner();
        let mut input = b"unrelated prefix".to_vec();
        input.extend_from_slice(&zip);

        let report = analyze(&input, "container.bin", &options()).unwrap();
        assert!(
            report
                .artifacts
                .iter()
                .any(|item| item.filename == "note.txt" && item.data == b"inside archive")
        );
    }
}
