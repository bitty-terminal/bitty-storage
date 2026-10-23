#!/usr/bin/env bash
# Shape test for scripts/package-component.sh: no Rust build, network, or R2.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
readonly SCRIPT="$REPO_ROOT/scripts/package-component.sh"
scratch_root="${TMPDIR:-/tmp/bitty}"
mkdir -p -- "$scratch_root"
tmp="$(mktemp -d "$scratch_root/package-component-test.XXXXXX")"
cleanup() { rm -rf -- "$tmp"; }
trap cleanup EXIT

version="$(awk -F'"' '$1 ~ /^[[:space:]]*version[[:space:]]*=/ { print $2; exit }' "$REPO_ROOT/bitty-component.toml")"
[[ -n "$version" ]] || {
	printf 'descriptor version is missing\n' >&2
	exit 1
}
printf '#!/bin/sh\necho bitty-storage %s\n' "$version" >"$tmp/bitty-storage"
chmod 755 "$tmp/bitty-storage"
printf '#!/bin/sh\necho bitty-storage %s arm\n' "$version" >"$tmp/bitty-storage-arm"
chmod 755 "$tmp/bitty-storage-arm"

output_dir="$tmp/dist"
mkdir -p -- "$output_dir"
"$SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage" --output "$output_dir/x86_64-unknown-linux-gnu.tar.gz"
"$SCRIPT" --version "$version" --target aarch64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage-arm" --output "$output_dir/aarch64-unknown-linux-gnu.tar.gz"

expected_files=$'SHA256SUMS\naarch64-unknown-linux-gnu.tar.gz\naarch64-unknown-linux-gnu.tar.gz.sha256\nx86_64-unknown-linux-gnu.tar.gz\nx86_64-unknown-linux-gnu.tar.gz.sha256'
actual_files="$(find "$output_dir" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort)"
[[ "$actual_files" == "$expected_files" ]] || {
	printf 'unexpected package files:\n%s\n' "$actual_files" >&2
	exit 1
}

(cd "$output_dir" && sha256sum -c SHA256SUMS >/dev/null)
for target in x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu; do
	archive="$output_dir/$target.tar.gz"
	members="$(tar -tzf "$archive" | LC_ALL=C sort)"
	[[ "$members" == $'bitty-component.toml\nbitty-storage' ]] || {
		printf 'unexpected archive members for %s:\n%s\n' "$target" "$members" >&2
		exit 1
	}
	extract="$tmp/$target"
	mkdir -p "$extract"
	tar -xzf "$archive" -C "$extract"
	grep -Fx 'name = "storage"' "$extract/bitty-component.toml" >/dev/null
	grep -Fx "version = \"$version\"" "$extract/bitty-component.toml" >/dev/null
	grep -Fx 'protocol = [1, 1]' "$extract/bitty-component.toml" >/dev/null
	grep -Fx 'executable = "bitty-storage"' "$extract/bitty-component.toml" >/dev/null
	digest="$(sha256sum "$extract/bitty-storage" | awk '{print $1}')"
	grep -Fx "sha256 = \"$digest\"" "$extract/bitty-component.toml" >/dev/null
done

# Existing archives must have a descriptor digest that matches the executable,
# even when the descriptor's non-digest metadata is otherwise canonical.
digest_dir="$tmp/digest-mismatch"
digest_extract="$tmp/digest-mismatch-extract"
mkdir -p -- "$digest_dir" "$digest_extract"
tar -xzf "$output_dir/x86_64-unknown-linux-gnu.tar.gz" -C "$digest_extract"
printf '#!/bin/sh\necho substituted\n' >"$digest_extract/bitty-storage"
chmod 755 "$digest_extract/bitty-storage"
tar -czf "$digest_dir/aarch64-unknown-linux-gnu.tar.gz" -C "$digest_extract" bitty-component.toml bitty-storage
if "$SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage" --output "$digest_dir/x86_64-unknown-linux-gnu.tar.gz" \
	>/dev/null 2>&1; then
	printf 'packager accepted an existing archive with a mismatched executable digest\n' >&2
	exit 1
fi

# A stale archive with a different descriptor version in the same output
# directory must stop the pack instead of producing mixed metadata.
stale_dir="$tmp/stale"
stale_extract="$tmp/stale-extract"
mkdir -p -- "$stale_dir" "$stale_extract"
tar -xzf "$output_dir/x86_64-unknown-linux-gnu.tar.gz" -C "$stale_extract"
sed -i 's/^version = ".*"$/version = "9.9.9"/' "$stale_extract/bitty-component.toml"
tar -czf "$stale_dir/aarch64-unknown-linux-gnu.tar.gz" -C "$stale_extract" bitty-component.toml bitty-storage
if "$SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage" --output "$stale_dir/x86_64-unknown-linux-gnu.tar.gz" \
	>/dev/null 2>&1; then
	printf 'packager accepted a mixed-version output directory\n' >&2
	exit 1
fi

if "$SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage" --output "$tmp/wrong-name.tgz" >/dev/null 2>&1; then
	printf 'packager accepted a non-target output name\n' >&2
	exit 1
fi

# A same-version archive whose name/executable/protocol drifted must also be
# rejected; only the per-binary sha256 line may differ.
drift_dir="$tmp/drift"
drift_extract="$tmp/drift-extract"
mkdir -p -- "$drift_dir" "$drift_extract"
tar -xzf "$output_dir/x86_64-unknown-linux-gnu.tar.gz" -C "$drift_extract"
sed -i 's/^executable = ".*"$/executable = "bitty-other"/' "$drift_extract/bitty-component.toml"
tar -czf "$drift_dir/aarch64-unknown-linux-gnu.tar.gz" -C "$drift_extract" bitty-component.toml bitty-storage
if "$SCRIPT" --version "$version" --target x86_64-unknown-linux-gnu \
	--binary "$tmp/bitty-storage" --output "$drift_dir/x86_64-unknown-linux-gnu.tar.gz" \
	>/dev/null 2>&1; then
	printf 'packager accepted a same-version archive with a drifted descriptor\n' >&2
	exit 1
fi

printf 'package-component.test: PASS\n'
