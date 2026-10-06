#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
app="$repo_root/src-tauri/target/release/bundle/macos/LayerSift.app"
output_dir="${1:-$repo_root/dist/macos}"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/layersift-package.XXXXXX")"
mounted=false

cleanup() {
  if [[ "$mounted" == true ]]; then
    hdiutil detach "$work_dir/mount" >/dev/null
  fi
  rm -rf "$work_dir"
}
trap cleanup EXIT

mkdir -p "$output_dir" "$work_dir/dmg-root" "$work_dir/mount" "$work_dir/zip"
codesign --verify --deep --strict --verbose=2 "$app"

# A temporary directory outside Desktop avoids Finder metadata on the app.
ditto "$app" "$work_dir/dmg-root/LayerSift.app"
ln -s /Applications "$work_dir/dmg-root/Applications"
xattr -cr "$work_dir/dmg-root/LayerSift.app"
codesign --verify --deep --strict --verbose=2 "$work_dir/dmg-root/LayerSift.app"

hdiutil create -volname LayerSift -srcfolder "$work_dir/dmg-root" -format UDZO -ov "$output_dir/LayerSift-macos-arm64.dmg"
ditto -c -k --sequesterRsrc --keepParent "$app" "$output_dir/LayerSift-macos-arm64.zip"

hdiutil attach -readonly -nobrowse -mountpoint "$work_dir/mount" "$output_dir/LayerSift-macos-arm64.dmg" >/dev/null
mounted=true
codesign --verify --deep --strict --verbose=2 "$work_dir/mount/LayerSift.app"
hdiutil detach "$work_dir/mount" >/dev/null
mounted=false

ditto -x -k "$output_dir/LayerSift-macos-arm64.zip" "$work_dir/zip"
codesign --verify --deep --strict --verbose=2 "$work_dir/zip/LayerSift.app"
