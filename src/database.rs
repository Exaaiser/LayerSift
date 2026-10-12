//! Locate an existing digest in ordinary SQLite tables without changing database contents.
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, limits::Limit, params, types::ValueRef};
use serde::Serialize;

pub const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Debug, Serialize)]
pub struct Cell {
    pub column: String,
    pub value: String,
    pub storage_type: String,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct RowKey {
    pub kind: String,
    pub fields: Vec<Cell>,
}

#[derive(Debug, Serialize)]
pub struct HashLocation {
    pub table: String,
    pub column: String,
    pub row_key: RowKey,
    pub matched_value: String,
    pub storage_type: String,
    pub context: Vec<Cell>,
}

#[derive(Debug, Serialize)]
pub struct SearchReport {
    pub input_hash: String,
    pub database_bytes: u64,
    pub text_matching: String,
    pub scanned_tables: usize,
    pub scanned_columns: usize,
    pub complete: bool,
    pub matches: Vec<HashLocation>,
    pub notes: Vec<String>,
}

struct Limits {
    tables: usize,
    columns: usize,
    matches: usize,
    duration: Duration,
}

#[derive(Clone)]
struct Column {
    name: String,
    pk: i64,
}

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn preview_expression(name: &str) -> String {
    let name = quote(name);
    // Limit returned values before converting SQLite cells into Rust strings.
    format!(
        "CASE WHEN typeof({name}) IN ('text','blob') THEN substr({name},1,180) ELSE {name} END, typeof({name}), coalesce(length({name}) > 180,0)"
    )
}

fn cell(row: &rusqlite::Row<'_>, index: usize, name: &str) -> rusqlite::Result<Cell> {
    let value = match row.get_ref(index)? {
        ValueRef::Null => "NULL".into(),
        ValueRef::Integer(value) => value.to_string(),
        ValueRef::Real(value) => value.to_string(),
        ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
        ValueRef::Blob(value) => hex::encode(value),
    };
    Ok(Cell {
        column: name.into(),
        value,
        storage_type: row.get(index + 1)?,
        truncated: row.get(index + 2)?,
    })
}

pub fn locate_hash(path: &Path, hash: &str) -> Result<SearchReport, String> {
    search(
        path,
        hash,
        Limits {
            tables: 64,
            columns: 256,
            matches: 100,
            duration: Duration::from_secs(10),
        },
    )
}

fn search(path: &Path, hash: &str, limits: Limits) -> Result<SearchReport, String> {
    let hash = hash.trim();
    if !(8..=1024).contains(&hash.len()) {
        return Err("Enter a hash value between 8 and 1024 bytes.".into());
    }
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("Choose a SQLite database file.".into());
    }
    let mut header = [0; 16];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut header))
        .map_err(|_| "This file does not have a SQLite database header.".to_string())?;
    if &header != SQLITE_HEADER {
        return Err("Choose a SQLite database file.".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|error| error.to_string())?;
    conn.busy_timeout(Duration::from_millis(250))
        .map_err(|error| error.to_string())?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, 1_048_576)
        .map_err(|error| error.to_string())?;
    conn.execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-8192; BEGIN;").map_err(|error| error.to_string())?;
    let started = Instant::now();
    let duration = limits.duration;
    conn.progress_handler(1000, Some(move || started.elapsed() >= duration))
        .map_err(|error| error.to_string())?;
    let is_hex = hash.len().is_multiple_of(2) && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
    let binary = is_hex.then(|| hex::decode(hash).expect("validated hexadecimal"));
    let mut report = SearchReport {
        input_hash: hash.into(),
        database_bytes: metadata.len(),
        text_matching: if is_hex {
            "Hexadecimal text ignores letter case; raw digest BLOBs are also matched."
        } else {
            "Exact text value, including letter case."
        }
        .into(),
        scanned_tables: 0,
        scanned_columns: 0,
        complete: true,
        matches: Vec::new(),
        notes: Vec::new(),
    };
    let mut statement = conn.prepare("SELECT name,wr FROM pragma_table_list WHERE schema='main' AND type='table' AND name NOT GLOB 'sqlite_*' ORDER BY name LIMIT ?1").map_err(|error| error.to_string())?;
    let tables = statement
        .query_map([limits.tables as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?))
        })
        .map_err(|error| error.to_string())?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|error| error.to_string())?;
    if tables.len() > limits.tables {
        report.complete = false;
        report.notes.push(format!(
            "Table limit reached; only the first {} ordinary tables were considered.",
            limits.tables
        ));
    }
    'tables: for (table, without_rowid) in tables.into_iter().take(limits.tables) {
        if started.elapsed() >= limits.duration {
            report.complete = false;
            report.notes.push("Search time limit reached.".into());
            break;
        }
        let columns = (|| -> rusqlite::Result<Vec<Column>> {
            let mut statement =
                conn.prepare(&format!("PRAGMA main.table_xinfo({})", quote(&table)))?;
            let rows = statement.query_map([], |row| {
                Ok((
                    Column {
                        name: row.get(1)?,
                        pk: row.get(5)?,
                    },
                    row.get::<_, i32>(6)?,
                ))
            })?;
            Ok(rows
                .collect::<rusqlite::Result<Vec<_>>>()?
                .into_iter()
                .filter(|(_, hidden)| *hidden == 0)
                .map(|(column, _)| column)
                .collect())
        })();
        let columns = match columns {
            Ok(columns) => columns,
            Err(error) => {
                report.complete = false;
                report
                    .notes
                    .push(format!("Could not inspect table {table:?}: {error}"));
                continue;
            }
        };
        report.scanned_tables += 1;
        let mut keys: Vec<_> = columns
            .iter()
            .filter(|column| column.pk > 0)
            .cloned()
            .collect();
        keys.sort_by_key(|column| column.pk);
        // SQLite rowid aliases can be shadowed by actual columns.
        let rowid = (!without_rowid)
            .then(|| {
                ["rowid", "_rowid_", "oid"].into_iter().find(|alias| {
                    !columns
                        .iter()
                        .any(|column| column.name.eq_ignore_ascii_case(alias))
                })
            })
            .flatten();
        let key_supported = keys.len() <= 16;
        if !key_supported {
            keys.clear();
            report.notes.push(format!("Table {table:?} has more than 16 primary-key fields; its key preview is unavailable."));
        }
        let context: Vec<_> = columns.iter().take(6).collect();
        let rowid_sql = rowid.map(quote).unwrap_or_else(|| "NULL".into());
        let key_sql: Vec<_> = keys
            .iter()
            .map(|column| preview_expression(&column.name))
            .collect();
        let context_sql: Vec<_> = context
            .iter()
            .map(|column| preview_expression(&column.name))
            .collect();
        for column in &columns {
            if report.scanned_columns >= limits.columns
                || report.matches.len() >= limits.matches
                || started.elapsed() >= limits.duration
            {
                report.complete = false;
                report.notes.push("Search stopped at the column, result, or time limit. Additional matches may exist.".into());
                break 'tables;
            }
            report.scanned_columns += 1;
            let name = quote(&column.name);
            let collation = if is_hex { "NOCASE" } else { "BINARY" };
            let mut fields = vec![rowid_sql.clone(), name.clone(), format!("typeof({name})")];
            fields.extend(key_sql.iter().cloned());
            fields.extend(context_sql.iter().cloned());
            let sql = format!(
                "SELECT {} FROM main.{} WHERE (typeof({name})='text' AND {name} COLLATE {collation}=?1) OR (typeof({name})='blob' AND {name}=?2) LIMIT ?3",
                fields.join(","),
                quote(&table)
            );
            let result = (|| -> rusqlite::Result<()> {
                let mut statement = conn.prepare(&sql)?;
                // Fetch one extra hit to distinguish a complete search from a capped one.
                let remaining = limits.matches - report.matches.len();
                let mut rows =
                    statement.query(params![hash, binary.as_deref(), remaining as i64 + 1])?;
                while let Some(row) = rows.next()? {
                    if report.matches.len() >= limits.matches {
                        report.complete = false;
                        report
                            .notes
                            .push("Result limit reached. Additional matches exist.".into());
                        break;
                    }
                    let matched_value = match row.get_ref(1)? {
                        ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
                        ValueRef::Blob(value) => hex::encode(value),
                        _ => unreachable!("query restricts value types"),
                    };
                    let mut key_fields = keys
                        .iter()
                        .enumerate()
                        .map(|(i, column)| cell(row, 3 + i * 3, &column.name))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    let use_pk = key_supported
                        && !key_fields.is_empty()
                        && key_fields.iter().all(|cell| cell.storage_type != "null");
                    let key_kind = if use_pk {
                        "primary key"
                    } else if let Some(value) = row.get::<_, Option<i64>>(0)? {
                        key_fields = vec![Cell {
                            column: rowid.unwrap().into(),
                            value: value.to_string(),
                            storage_type: "integer".into(),
                            truncated: false,
                        }];
                        "rowid"
                    } else {
                        key_fields.clear();
                        "unavailable"
                    };
                    let offset = 3 + keys.len() * 3;
                    let context = context
                        .iter()
                        .enumerate()
                        .map(|(i, column)| cell(row, offset + i * 3, &column.name))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    report.matches.push(HashLocation {
                        table: table.clone(),
                        column: column.name.clone(),
                        row_key: RowKey {
                            kind: key_kind.into(),
                            fields: key_fields,
                        },
                        matched_value,
                        storage_type: row.get(2)?,
                        context,
                    });
                }
                Ok(())
            })();
            if let Err(error) = result {
                report.complete = false;
                report.notes.push(format!(
                    "Could not fully search {table:?}.{:?}: {error}",
                    column.name
                ));
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HASH: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(sql: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "layersift-db-{}-{}.sqlite",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            Connection::open(&path).unwrap().execute_batch(sql).unwrap();
            Self(path)
        }
        fn conn(&self) -> Connection {
            Connection::open(&self.0).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn finds_all_text_and_blob_locations_and_preserves_database_bytes() {
        let fixture = Fixture::new(
            "CREATE TABLE users(id INTEGER PRIMARY KEY,email TEXT,hash TEXT); CREATE TABLE files(id TEXT PRIMARY KEY,digest BLOB);",
        );
        let conn = fixture.conn();
        conn.execute(
            "INSERT INTO users VALUES (42,'user@example.com',?1),(43,'other@example.com',?2)",
            params![HASH, HASH.to_uppercase()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO files VALUES ('file-1',?1)",
            [hex::decode(HASH).unwrap()],
        )
        .unwrap();
        drop(conn);
        let before = fs::read(&fixture.0).unwrap();
        let result = locate_hash(&fixture.0, HASH).unwrap();
        assert!(result.complete);
        assert_eq!(result.matches.len(), 3);
        assert_eq!(result.matches[0].table, "files");
        assert_eq!(result.matches[0].storage_type, "blob");
        assert_eq!(result.matches[0].row_key.kind, "primary key");
        assert_eq!(result.matches[0].row_key.fields[0].value, "file-1");
        assert!(result.matches.iter().any(|item| item.table == "users"
            && item.column == "hash"
            && item.row_key.fields[0].value == "42"));
        assert_eq!(fs::read(&fixture.0).unwrap(), before);
    }

    #[test]
    fn locates_composite_keys_in_without_rowid_tables() {
        let fixture = Fixture::new(
            "CREATE TABLE records(tenant TEXT,id INTEGER,hash TEXT,PRIMARY KEY(tenant,id)) WITHOUT ROWID;",
        );
        fixture
            .conn()
            .execute("INSERT INTO records VALUES ('demo',7,?1)", [HASH])
            .unwrap();
        let report = locate_hash(&fixture.0, HASH).unwrap();
        let fields = &report.matches[0].row_key.fields;
        assert_eq!(report.matches[0].row_key.kind, "primary key");
        assert_eq!(
            (&fields[0].column, &fields[0].value),
            (&"tenant".into(), &"demo".into())
        );
        assert_eq!(
            (&fields[1].column, &fields[1].value),
            (&"id".into(), &"7".into())
        );
    }

    #[test]
    fn falls_back_to_an_unshadowed_rowid_for_unkeyed_or_nullable_keys() {
        let fixture =
            Fixture::new("CREATE TABLE records(rowid TEXT,key TEXT PRIMARY KEY,hash TEXT);");
        fixture
            .conn()
            .execute(
                "INSERT INTO records VALUES ('not-the-rowid',NULL,?1)",
                [HASH],
            )
            .unwrap();
        let report = locate_hash(&fixture.0, HASH).unwrap();
        assert_eq!(report.matches[0].row_key.kind, "rowid");
        assert_eq!(report.matches[0].row_key.fields[0].column, "_rowid_");
        assert_eq!(report.matches[0].row_key.fields[0].value, "1");
    }

    #[test]
    fn does_not_invent_a_key_when_every_rowid_alias_is_shadowed() {
        let fixture =
            Fixture::new("CREATE TABLE records(rowid TEXT,_rowid_ TEXT,oid TEXT,hash TEXT);");
        fixture
            .conn()
            .execute("INSERT INTO records VALUES ('a','b','c',?1)", [HASH])
            .unwrap();
        let report = locate_hash(&fixture.0, HASH).unwrap();
        assert_eq!(report.matches[0].row_key.kind, "unavailable");
        assert!(report.matches[0].row_key.fields.is_empty());
    }

    #[test]
    fn binds_input_and_quotes_unusual_identifiers() {
        let fixture = Fixture::new(
            "CREATE TABLE \"accounts\"\" table\"(id INTEGER PRIMARY KEY,\"hash\"\" field\" TEXT);",
        );
        let input = "'; DROP TABLE users; --";
        fixture
            .conn()
            .execute(
                "INSERT INTO \"accounts\"\" table\" VALUES (1,?1),(2,'unrelated value')",
                [input],
            )
            .unwrap();
        let report = locate_hash(&fixture.0, input).unwrap();
        assert!(report.complete);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].table, "accounts\" table");
        assert_eq!(report.matches[0].column, "hash\" field");
        assert_eq!(report.matches[0].row_key.fields[0].value, "1");
    }

    #[test]
    fn non_hex_text_matches_case_exactly_and_does_not_search_views() {
        let fixture = Fixture::new(
            "CREATE TABLE records(id INTEGER PRIMARY KEY,hash TEXT); CREATE VIEW misleading AS SELECT hash FROM records;",
        );
        fixture
            .conn()
            .execute(
                "INSERT INTO records VALUES (1,'$demo$MixedCase'),(2,'$demo$mixedcase')",
                [],
            )
            .unwrap();
        let report = locate_hash(&fixture.0, "$demo$MixedCase").unwrap();
        assert!(report.complete);
        assert_eq!(report.scanned_tables, 1);
        assert_eq!(report.matches.len(), 1);
        assert_eq!(report.matches[0].row_key.fields[0].value, "1");
    }

    #[test]
    fn reports_partial_searches_instead_of_claiming_no_more_matches() {
        let fixture = Fixture::new("CREATE TABLE records(id INTEGER PRIMARY KEY,hash TEXT);");
        fixture
            .conn()
            .execute("INSERT INTO records VALUES (1,?1),(2,?1),(3,?1)", [HASH])
            .unwrap();
        let report = search(
            &fixture.0,
            HASH,
            Limits {
                tables: 64,
                columns: 256,
                matches: 2,
                duration: Duration::from_secs(10),
            },
        )
        .unwrap();
        assert_eq!(report.matches.len(), 2);
        assert!(!report.complete);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("Result limit"))
        );
        let report = search(
            &fixture.0,
            HASH,
            Limits {
                tables: 64,
                columns: 1,
                matches: 100,
                duration: Duration::from_secs(10),
            },
        )
        .unwrap();
        assert!(!report.complete);
        let report = search(
            &fixture.0,
            HASH,
            Limits {
                tables: 64,
                columns: 256,
                matches: 100,
                duration: Duration::ZERO,
            },
        )
        .unwrap();
        assert!(!report.complete);
    }

    #[test]
    fn limits_context_previews_and_rejects_non_databases() {
        let fixture =
            Fixture::new("CREATE TABLE records(id INTEGER PRIMARY KEY,hash TEXT,note TEXT);");
        fixture
            .conn()
            .execute(
                "INSERT INTO records VALUES (1,?1,?2)",
                params![HASH, "x".repeat(400)],
            )
            .unwrap();
        let report = locate_hash(&fixture.0, HASH).unwrap();
        let note = report.matches[0]
            .context
            .iter()
            .find(|cell| cell.column == "note")
            .unwrap();
        assert!(note.truncated);
        assert_eq!(note.value.len(), 180);
        assert!(locate_hash(&fixture.0, "tiny").is_err());
        fs::write(&fixture.0, b"this is not SQLite").unwrap();
        assert!(locate_hash(&fixture.0, HASH).is_err());
        let missing = fixture.0.with_extension("missing");
        assert!(locate_hash(&missing, HASH).is_err());
        assert!(!missing.exists());
    }
}
