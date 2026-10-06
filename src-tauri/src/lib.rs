use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use layersift::analysis::{Artifact, Options, analyze};
use layersift::hashing::{digest, digest_candidates, explain_hash};
use serde::Deserialize;
use serde_json::{Value, json};
use tauri::Manager;

const MAX_INPUT: u64 = 16_000_000;

struct StoredResult {
    report: Value,
    files: Vec<(String, Vec<u8>)>,
}

#[derive(Default)]
struct AppState {
    last: Mutex<Option<StoredResult>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ActionRequest {
    mode: String,
    text: Option<String>,
    file_path: Option<String>,
    algorithm: Option<String>,
    caesar_shift: Option<i32>,
    xor_key: Option<String>,
    zip_password: Option<String>,
    auto_xor: Option<bool>,
}

fn safe_name(name: &str) -> String {
    let value: String = name
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
    if value.is_empty() {
        "output.bin".into()
    } else {
        value
    }
}

fn output_root(app: &tauri::AppHandle, destination: Option<&str>) -> Result<PathBuf, String> {
    if let Some(destination) = destination.filter(|value| !value.trim().is_empty()) {
        let path = PathBuf::from(destination);
        if !path.is_dir() {
            return Err("The selected save folder is no longer available. Choose another folder in Settings.".into());
        }
        return Ok(path);
    }
    let root = app
        .path()
        .document_dir()
        .map_err(|error| error.to_string())?
        .join("LayerSift");
    fs::create_dir_all(&root).map_err(|error| error.to_string())?;
    Ok(root)
}

fn valid_folder_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 80
        && !name.ends_with(' ')
        && !name.ends_with('.')
        && !name
            .chars()
            .any(|character| character.is_control() || "/\\:*?\"<>|".contains(character))
}

fn write_result(root: &Path, stored: &StoredResult) -> Result<PathBuf, String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();
    let folder = (0..1000)
        .map(|index| root.join(format!("analysis-{timestamp}-{index:03}")))
        .find(|path| !path.exists())
        .ok_or("Could not create a new report folder.")?;
    fs::create_dir(&folder).map_err(|error| error.to_string())?;
    let pretty = serde_json::to_string_pretty(&stored.report).map_err(|error| error.to_string())?;
    fs::write(folder.join("report.json"), &pretty).map_err(|error| error.to_string())?;
    let file_list = if stored.files.is_empty() {
        "No extracted files.".to_string()
    } else {
        stored
            .files
            .iter()
            .map(|(name, _)| format!("- {name}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let markdown = format!(
        "# LayerSift report\n\nSaved locally.\n\n## Summary\n\n{pretty}\n\n## Files\n\n{file_list}\n"
    );
    fs::write(folder.join("report.md"), markdown).map_err(|error| error.to_string())?;
    for (name, bytes) in &stored.files {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(folder.join(name))
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
    }
    Ok(folder)
}

fn readable(data: &[u8]) -> bool {
    if data.contains(&0) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if text.trim().is_empty() {
        return false;
    }
    let sample: Vec<char> = text.chars().take(4096).collect();
    sample
        .iter()
        .filter(|character| !character.is_control() || matches!(character, '\t' | '\n' | '\r'))
        .count()
        * 10
        >= sample.len() * 9
}

fn display_text(data: &[u8]) -> Option<String> {
    if data.len() > 64 * 1024
        || data.starts_with(b"%PDF-")
        || data.starts_with(b"\x89PNG\r\n\x1a\n")
        || data.starts_with(b"\xff\xd8\xff")
        || data.starts_with(b"PK\x03\x04")
        || !readable(data)
    {
        return None;
    }
    let text = std::str::from_utf8(data).ok()?.trim().to_string();
    if let Ok(value) = serde_json::from_str::<Value>(&text) {
        return serde_json::to_string_pretty(&value).ok();
    }
    Some(text)
}

fn present(artifacts: &[Artifact]) -> (String, Option<String>) {
    let chosen = artifacts.iter().max_by_key(|item| {
        (
            display_text(&item.data).is_some(),
            item.steps.len(),
            item.data.len(),
        )
    });
    let Some(item) = chosen else {
        return ("No recognized content".into(), None);
    };
    if let Some(text) = display_text(&item.data) {
        let kind = if serde_json::from_str::<Value>(text.trim()).is_ok() {
            "JSON content found"
        } else {
            "Text content found"
        };
        return (kind.to_string(), (text.len() <= 64 * 1024).then_some(text));
    }
    ("File content found".into(), None)
}

fn looks_like_opaque_digest(candidates: &[&str], artifacts: &[Artifact]) -> bool {
    !candidates.is_empty()
        && artifacts.iter().all(|item| {
            item.kind == "binary" && item.steps.len() == 1 && item.steps[0] == "hex decode"
        })
}

fn load_input(
    text: Option<String>,
    file_path: Option<String>,
) -> Result<(String, Vec<u8>), String> {
    match (text, file_path) {
        (Some(text), None) if !text.trim().is_empty() => {
            if text.len() as u64 > MAX_INPUT {
                return Err("Input exceeds the 16 MB limit.".into());
            }
            Ok(("Text input".into(), text.into_bytes()))
        }
        (None, Some(path)) => {
            let path = PathBuf::from(path);
            let metadata = fs::metadata(&path).map_err(|error| error.to_string())?;
            if !metadata.is_file() {
                return Err("Choose a file.".into());
            }
            if metadata.len() > MAX_INPUT {
                return Err("File exceeds the 16 MB limit.".into());
            }
            let bytes = fs::read(&path).map_err(|error| error.to_string())?;
            Ok((path.display().to_string(), bytes))
        }
        _ => Err("Enter text or choose a file.".into()),
    }
}

#[tauri::command]
fn run_action(request: ActionRequest, state: tauri::State<'_, AppState>) -> Result<Value, String> {
    let ActionRequest {
        mode,
        text,
        file_path,
        algorithm,
        caesar_shift,
        xor_key,
        zip_password,
        auto_xor,
    } = request;
    let (source, bytes) = load_input(text, file_path)?;
    let (response, stored) = match mode.as_str() {
        "analyze" => {
            if caesar_shift.is_some_and(|shift| !(0..=25).contains(&shift)) {
                return Err("Caesar shift must be between 0 and 25.".into());
            }
            let options = Options {
                depth: 4,
                auto_xor: auto_xor.unwrap_or(true),
                caesar_shift,
                xor_key: xor_key
                    .filter(|value| !value.is_empty())
                    .map(String::into_bytes),
                zip_password: zip_password
                    .filter(|value| !value.is_empty())
                    .map(String::into_bytes),
            };
            let analysis = analyze(&bytes, &source, &options).map_err(|error| error.to_string())?;
            let summary = analysis.summary();
            let candidates = std::str::from_utf8(&bytes)
                .ok()
                .map(|value| digest_candidates(value.trim()))
                .unwrap_or_default();
            let only_hex_binary = looks_like_opaque_digest(&candidates, &analysis.artifacts);
            let (headline, value, explanation, status, files) = if only_hex_binary {
                (
                    "Possible hash format".to_string(), None,
                    "The length and character set fit several hash algorithms. This value alone cannot identify the exact algorithm or recover the original input. Reading its hexadecimal bytes does not reverse a hash.".to_string(),
                    "Format match".to_string(), Vec::new()
                )
            } else {
                let (headline, value) = present(&analysis.artifacts);
                let files: Vec<(String, Vec<u8>)> = analysis
                    .artifacts
                    .iter()
                    .enumerate()
                    .map(|(index, item)| {
                        (
                            format!("{:04}_{}", index + 1, safe_name(&item.filename)),
                            item.data.clone(),
                        )
                    })
                    .collect();
                let explanation = if files.is_empty() {
                    "No recognizable encoding layer or extractable file was found in this input."
                        .to_string()
                } else {
                    "Recognized layers were opened. Sources and transformation steps for recovered content are listed below.".to_string()
                };
                let status = if files.is_empty() {
                    "No result"
                } else {
                    "Content found"
                }
                .to_string();
                (headline, value, explanation, status, files)
            };
            let can_copy = value.is_some();
            let mut report = json!({
                "mode": "analyze", "headline": headline, "explanation": explanation,
                "status": status, "source": source, "inputBytes": bytes.len(), "candidates": candidates,
                "report": summary, "value": value, "canCopy": can_copy
            });
            if only_hex_binary {
                report["report"]["artifacts"] = json!([]);
            }
            (report.clone(), StoredResult { report, files })
        }
        "base64" => {
            let encoded = STANDARD.encode(&bytes);
            let preview: String = encoded.chars().take(1000).collect();
            let full = if encoded.len() <= 64 * 1024 {
                Some(encoded.clone())
            } else {
                None
            };
            let report = json!({
                "mode": "base64", "source": source, "input_bytes": bytes.len(),
                "output_characters": encoded.len(), "preview": preview
            });
            (
                json!({
                    "mode": "base64", "headline": "Base64 created",
                    "explanation": "The input was encoded as Base64 text. Base64 is reversible encoding, not encryption.",
                    "status": "Ready", "source": source, "inputBytes": bytes.len(), "candidates": [],
                    "report": report, "value": full, "preview": preview, "canCopy": full.is_some()
                }),
                StoredResult {
                    report,
                    files: vec![("output.base64.txt".into(), encoded.into_bytes())],
                },
            )
        }
        "hash" => {
            let algorithm = algorithm.unwrap_or_else(|| "sha256".into());
            let value = digest(&algorithm, &bytes).map_err(|error| error.to_string())?;
            let method = explain_hash(&algorithm).map_err(|error| error.to_string())?;
            let report = json!({
                "mode": "hash", "source": source, "algorithm": algorithm,
                "digest": value, "input_bytes": bytes.len(), "method": method
            });
            (
                json!({
                    "mode": "hash", "headline": "Hash created",
                    "explanation": method, "status": "Ready", "source": source, "inputBytes": bytes.len(),
                    "candidates": [algorithm], "report": report, "value": value, "canCopy": true
                }),
                StoredResult {
                    report,
                    files: vec![("digest.txt".into(), format!("{value}\n").into_bytes())],
                },
            )
        }
        _ => return Err("Unknown action.".into()),
    };
    *state
        .last
        .lock()
        .map_err(|_| "Could not access session state.")? = Some(stored);
    Ok(response)
}

#[tauri::command]
fn create_output_folder(
    app: tauri::AppHandle,
    parent_path: Option<String>,
    name: String,
) -> Result<String, String> {
    let name = name.trim();
    if !valid_folder_name(name) {
        return Err(
            "Enter a folder name without slashes or special characters (up to 80 bytes).".into(),
        );
    }
    let parent = output_root(&app, parent_path.as_deref())?;
    let folder = parent.join(name);
    fs::create_dir(&folder).map_err(|error| error.to_string())?;
    Ok(folder.display().to_string())
}

#[tauri::command]
fn save_result(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    destination: Option<String>,
) -> Result<String, String> {
    let guard = state
        .last
        .lock()
        .map_err(|_| "Could not access session state.")?;
    let stored = guard
        .as_ref()
        .ok_or("Analyze or create a value before saving.")?;
    let root = output_root(&app, destination.as_deref())?;
    let folder = write_result(&root, stored)?;
    Ok(folder.display().to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::default())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            run_action,
            save_result,
            create_output_folder
        ])
        .run(tauri::generate_context!())
        .expect("desktop application failed");
}

#[cfg(test)]
mod resolve_tests {
    use base64::Engine;
    use layersift::analysis::{Options, analyze};

    use super::{
        STANDARD, StoredResult, looks_like_opaque_digest, present, valid_folder_name, write_result,
    };
    use layersift::hashing::digest_candidates;

    fn opened(input: &str) -> layersift::analysis::Analysis {
        analyze(
            input.as_bytes(),
            "text",
            &Options {
                depth: 4,
                auto_xor: true,
                ..Options::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn email_inside_base64_is_extracted() {
        let encoded = STANDARD.encode("user@example.com");
        let (headline, value) = present(&opened(&encoded).artifacts);
        assert_eq!(headline, "Text content found");
        assert_eq!(value.as_deref(), Some("user@example.com"));
    }

    #[test]
    fn pdf_is_presented_as_file_even_when_header_is_readable() {
        let encoded = STANDARD.encode(b"%PDF-1.4\nsample\n%%EOF");
        let (headline, value) = present(&opened(&encoded).artifacts);
        assert_eq!(headline, "File content found");
        assert_eq!(value, None);
    }

    #[test]
    fn opaque_hex_is_not_presented_as_recovered_text() {
        let input = "a".repeat(64);
        let analysis = opened(&input);
        assert!(analysis.artifacts.is_empty());
        let (headline, value) = present(&analysis.artifacts);
        assert_eq!(headline, "No recognized content");
        assert_eq!(value, None);
        assert!(looks_like_opaque_digest(
            &digest_candidates(&input),
            &analysis.artifacts
        ));
    }

    #[test]
    fn writes_report_and_files_under_selected_folder() {
        let root = std::env::temp_dir().join(format!(
            "layersift-save-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let stored = StoredResult {
            report: serde_json::json!({"mode": "analyze"}),
            files: vec![("sample.txt".into(), b"hello".to_vec())],
        };
        let folder = write_result(&root, &stored).unwrap();
        assert_eq!(folder.parent(), Some(root.as_path()));
        assert!(folder.join("report.json").is_file());
        assert!(folder.join("report.md").is_file());
        assert_eq!(std::fs::read(folder.join("sample.txt")).unwrap(), b"hello");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_folder_names_that_escape_the_selected_location() {
        assert!(valid_folder_name("Project results"));
        for name in [
            "",
            ".",
            "..",
            "../outside",
            "nested/folder",
            "nested\\folder",
            "bad:name",
        ] {
            assert!(!valid_folder_name(name));
        }
    }
}
