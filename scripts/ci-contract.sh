#!/usr/bin/env bash
# CI contract: the workflow must run the Rust product gates, and the toolchain
# must come from rust-toolchain.toml. Usage: scripts/ci-contract.sh [ROOT]
set -euo pipefail

root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
workflow="$root/.github/workflows/ci.yml"
justfile="$root/justfile"

die() {
	echo "ci-contract: $*" >&2
	exit 1
}

test -s "$workflow" || die "$workflow is missing"
grep -Eq '^[[:space:]]*(-[[:space:]]*)?run: just product[[:space:]]*$' "$workflow" ||
	die "$workflow must invoke 'just product' (Rust suite)"

# Recipe command lines only: strip indentation and just line modifiers, drop
# blank and comment lines, so a commented-out gate never satisfies the check.
product_commands="$(awk '
    /^product:/ { in_recipe = 1; next }
    in_recipe && /^[^[:space:]#]/ { exit }
    in_recipe {
        sub(/^[[:space:]]+/, "")
        sub(/^[@+-]+/, "")
        if ($0 == "" || $0 ~ /^#/) next
        print
    }
' "$justfile")"
test -n "$product_commands" || die "$justfile has no executable product recipe lines"

for gate in 'cargo fmt' 'cargo clippy' 'cargo test'; do
	grep -Eq "(^|[[:space:]])${gate}([[:space:]]|$)" <<<"$product_commands" ||
		die "the product recipe must run $gate"
done

# A literal channel (or a RUSTUP_TOOLCHAIN override) in .github would drift
# from the repository pin; the value must be an expression resolving to it.
if grep -REn \
	-e '^[[:space:]]*toolchain:[[:space:]]*[^$[:space:]]' \
	-e '^[[:space:]]*(-[[:space:]]*)?RUSTUP_TOOLCHAIN:' \
	-e 'RUSTUP_TOOLCHAIN=' \
	"$root/.github"; then
	die 'pin the Rust toolchain in rust-toolchain.toml, not in .github'
fi

echo 'ci-contract: CI runs the product gates; toolchain pinned by rust-toolchain.toml'
