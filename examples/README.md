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
