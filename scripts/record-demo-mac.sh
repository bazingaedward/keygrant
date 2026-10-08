#!/bin/zsh
# keygrant Mac demo GIF: approval popup -> injection -> redaction
set -e
OUT="$(mktemp -d)"
# throwaway vault so the demo never lists the recorder's real secrets
export XDG_CONFIG_HOME="$OUT/config"
VAULT="$XDG_CONFIG_HOME/keygrant/vault.json"

cleanup() {
  keygrant revoke --all >/dev/null 2>&1 || true
  keygrant rm STRIPE_KEY >/dev/null 2>&1 || true
}
trap cleanup EXIT

run() {
  osascript -e 'on run argv' \
    -e 'tell application "Terminal" to do script (item 1 of argv) in front window' \
    -e 'end run' "$1" >/dev/null
}

# macOS places the approval dialog around the upper third of the main
# display; put the window's title bar above that so the capture region
# (window content only) contains the whole dialog but never the title
read SW SH <<<"$(osascript -l JavaScript -e \
  'ObjC.import("AppKit"); var f=$.NSScreen.mainScreen.frame.size; f.width+" "+f.height')"
W=1000; H=600
X=$(( (SW - W) / 2 )); Y=$(( SH / 3 - 210 ))

osascript <<EOF
tell application "Terminal"
  activate
  do script "export XDG_CONFIG_HOME='$XDG_CONFIG_HOME' PROMPT='%F{green}❯%f '; clear"
  set bounds of front window to {$X, $Y, $((X + W)), $((Y + H))}
  try
    set font size of selected tab of front window to 16
  end try
end tell
EOF
sleep 2
run "clear; echo"
sleep 1

# screencapture -v stops when a character arrives on stdin (it ignores SIGINT)
mkfifo "$OUT/ctl"
screencapture -v -R $((X + 2)),$((Y + 44)),$((W - 4)),$((H - 48)) "$OUT/demo_raw.mov" <"$OUT/ctl" &
REC=$!
exec 3>"$OUT/ctl"
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

print -u3 x
exec 3>&-
wait $REC 2>/dev/null || true

ffmpeg -y -v error -i "$OUT/demo_raw.mov" \
  -vf "fps=8,scale=960:-1:flags=lanczos,palettegen" "$OUT/palette.png"
ffmpeg -y -v error -i "$OUT/demo_raw.mov" -i "$OUT/palette.png" \
  -lavfi "fps=8,scale=960:-1:flags=lanczos[x];[x][1:v]paletteuse" \
  "$OUT/demo-mac.gif"
echo "$OUT/demo-mac.gif"
