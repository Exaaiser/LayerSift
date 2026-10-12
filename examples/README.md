# Try LayerSift

These small fixtures contain synthetic data. Download the repository or copy a file locally, then select it in **Resolve**. Recovered content, source locations, transformation steps, sizes, and fingerprints appear in the result pages. **Save result** writes the full report and recovered files into the folder selected in Settings.

| File | Expected result |
| --- | --- |
| `emails.json` | `user@example.com`, found at `$.contact.email_base64` after Base64 decoding. |
| `emails.sql` | `user@example.com`, recovered from a quoted SQL value. |
| `layered.txt` | `Three reversible layers reveal this message.` after Base64 → gzip → Base64. Intermediate layers are also reported. |
| `embedded-image.json` | A valid 1 × 1 PNG image, recovered from the Base64 attachment. Its bytes begin with `89 50 4E 47 0D 0A 1A 0A`. |
| `password-protected.zip` | `note.txt`, containing `A known password opens this demo archive.` Use the known demo password **`layersift-demo`**. This fixture uses legacy ZIP encryption solely to demonstrate extraction. |
| `checksum.txt` + `checksum.sha256` | Select **Create → SHA-256**, enable **Verify a file checksum**, choose `checksum.txt`, and paste the value from `checksum.sha256`. The result should be **Match**. Changing one digest character should produce **Mismatch**. |

The ZIP password and desktop checksum controls are in the development source after v0.3.0. The released v0.3.0 CLI can already run the same examples:

```sh
./layersift inspect --file examples/emails.json --json
./layersift inspect --file examples/layered.txt --json
./layersift extract --file examples/embedded-image.json --out ./recovered
./layersift extract --file examples/password-protected.zip --zip-password layersift-demo --out ./unpacked
```

The exact expected recovered SHA-256 values and transformation steps are in `expected.json`. To check them against a source build:

```sh
cargo build --release --locked
python3 scripts/check-examples.py
```

On Windows, use `python scripts/check-examples.py`; the script selects `layersift.exe` automatically. It needs only Python's standard library and a built CLI.

## SQLite hash lookup

`hash-locations.sqlite` is a synthetic database for the development source after v0.3.0. Choose it in **Resolve**, then paste this hash into **Find hash**:

```text
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

Expected locations:

| Table | Column | Record key | Storage |
| --- | --- | --- | --- |
| `events` | `checksum` | `tenant = demo`, `event_id = 7` | Uppercase hex TEXT, composite primary key in a WITHOUT ROWID table |
| `files` | `digest` | `id = file-1` | Raw digest BLOB |
| `users` | `password_hash` | `id = 42` | Lowercase hex TEXT |

The fixture uses the known SHA-256 digest of `hello`; no real credentials or user records are included. The lookup identifies stored values without attempting to recover the original input. Database rows use record keys rather than source file line numbers.

After building the source CLI, `scripts/check-examples.py` also verifies these three locations against `expected.json`.
