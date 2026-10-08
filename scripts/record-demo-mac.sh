#!/bin/zsh
# keygrant Mac demo GIF: approval popup -> injection -> redaction
set -e
GIFDIR="${0:A:h}"
VAULT="$HOME/.config/keygrant/vault.json"

keygrant revoke --all >/dev/null 2>&1 || true
keygrant rm STRIPE_KEY >/dev/null 2>&1 || true

run() {
  osascript -e 'on run argv' \
    -e 'tell application "Terminal" to do script (item 1 of argv) in front window' \
    -e 'end run' "$1" >/dev/null
}

osascript <<'EOF'
tell application "Terminal"
  activate
  do script "export PROMPT='%F{green}❯%f '; clear"
  set bounds of front window to {240, 140, 1240, 660}
  try
    set font size of selected tab of front window to 16
  end try
end tell
EOF
sleep 2
run "clear"
sleep 1

# capture ONLY the window content area (below title bar) — titles never appear
screencapture -v -R 242,172,996,484 "$GIFDIR/demo_raw.mov" &
REC=$!
sleep 2

run "echo 'sk-live-51HxDEMOonly0000' | keygrant set STRIPE_KEY --desc 'Stripe secret'"
sleep 3
run "keygrant list"
sleep 3.5
# native approval dialog appears here -> human clicks Allow
run "keygrant exec STRIPE_KEY -- sh -c 'echo charging API using \$STRIPE_KEY'"
for i in {1..90}; do
  uc=$(python3 -c "import json;print(json.load(open('$VAULT'))['secrets']['STRIPE_KEY']['use_count'])" 2>/dev/null || echo 0)
  [ "$uc" != "0" ] && break
  sleep 0.5
done
sleep 2.5
run "keygrant exec --redact STRIPE_KEY -- sh -c 'echo \$STRIPE_KEY'"
sleep 5

kill -INT $REC
wait $REC 2>/dev/null || true

keygrant revoke --all >/dev/null 2>&1 || true
keygrant rm STRIPE_KEY >/dev/null 2>&1 || true

ffmpeg -y -v error -i "$GIFDIR/demo_raw.mov" \
  -vf "fps=8,scale=960:-1:flags=lanczos,palettegen" "$GIFDIR/palette.png"
ffmpeg -y -v error -i "$GIFDIR/demo_raw.mov" -i "$GIFDIR/palette.png" \
  -lavfi "fps=8,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse" \
  "$GIFDIR/demo-mac.gif"
ls -la "$GIFDIR/demo-mac.gif"
