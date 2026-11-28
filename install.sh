#!/usr/bin/env bash
# Install pi-bitwarden from GitHub (a pi package = upgradable, not a copy).
#
#   ./install.sh          # pi install git:github.com/hljhljhlj/pi-bitwarden
#   ./install.sh --omp    # omp plugin install git+ssh://...
#   ./install.sh --dev    # symlink this checkout into ~/.pi/agent/extensions/
#
# Upgrade later:  pi update git:github.com/hljhljhlj/pi-bitwarden
#                 omp plugin install git+ssh://git@github.com/hljhljhlj/pi-bitwarden.git --force
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_PI="git:github.com/hljhljhlj/pi-bitwarden"
SRC_OMP="git+ssh://git@github.com/hljhljhlj/pi-bitwarden.git"
EXT_DIR="$HOME/.pi/agent/extensions"

mkdir -p "$HOME/.bw/pi-extension"
if [[ ! -f "$HOME/.bw/pi-extension/config.json" ]]; then
	cp "$DIR/config.example.json" "$HOME/.bw/pi-extension/config.json"
	echo "Created ~/.bw/pi-extension/config.json (defaults)"
fi

if [[ "${1:-}" == "--omp" ]]; then
	omp plugin install "$SRC_OMP" --force
	echo "Upgrade: omp plugin install $SRC_OMP --force"
elif [[ "${1:-}" == "--dev" ]]; then
	mkdir -p "$EXT_DIR"
	ln -sfn "$DIR/bitwarden.ts" "$EXT_DIR/bitwarden.ts"
	echo "Dev install: $EXT_DIR/bitwarden.ts -> $DIR/bitwarden.ts"
	echo "Edits here take effect on the next /reload inside pi."
else
	# A package install and the extensions/ symlink would load twice.
	rm -f "$EXT_DIR/bitwarden.ts"
	pi install "$SRC_PI"
	echo "Upgrade: pi update $SRC_PI"
fi

echo "Requires: bw CLI logged in (bw login), zenity for desktop prompts."
