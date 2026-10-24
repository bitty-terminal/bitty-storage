#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
test_script="$root/scripts/ci-contract.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/.github/workflows"
cp "$root/.github/workflows/ci.yml" "$tmp/.github/workflows/ci.yml"
cp "$root/justfile" "$tmp/justfile"
cp "$test_script" "$tmp/ci-contract.sh"

"$tmp/ci-contract.sh" "$tmp" >/dev/null

for gate in 'cargo fmt' 'cargo clippy' 'cargo test'; do
	case "$gate" in
	'cargo clippy')
		sed 's|^    RUSTFLAGS=|    # RUSTFLAGS=|' "$root/justfile" >"$tmp/justfile"
		;;
	*)
		sed "s|^    ${gate}|    # ${gate}|" "$root/justfile" >"$tmp/justfile"
		;;
	esac
	if "$tmp/ci-contract.sh" "$tmp" >/dev/null 2>&1; then
		echo "ci-contract test: commented ${gate} was accepted" >&2
		exit 1
	fi
	cp "$root/justfile" "$tmp/justfile"
done

cat >"$tmp/justfile" <<'EOF'
product:
    cargo fmt --all -- --check # cargo clippy # cargo test
EOF
if "$tmp/ci-contract.sh" "$tmp" >/dev/null 2>&1; then
	echo 'ci-contract test: inline-comment-only fake gates were accepted' >&2
	exit 1
fi

sed -E '/^    (cargo fmt|RUSTFLAGS=.*cargo clippy|cargo test)/s/^/#/' \
	"$root/justfile" >"$tmp/justfile"
if "$tmp/ci-contract.sh" "$tmp" >/dev/null 2>&1; then
	echo 'ci-contract test: an all-comment product recipe was accepted' >&2
	exit 1
fi

echo 'ci-contract test: negative comment-out cases passed'
