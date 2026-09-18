#!/data/data/com.termux/files/usr/bin/bash
# demo.sh — the script recorded into assets/demo.cast / assets/demo.gif.
# Prints each dsh invocation the way a shell would, then runs it for real.
set -u

p() { printf '\033[1;32m$\033[0m %s\n' "$1"; sleep 0.7; }

p "dsh id"
dsh id
printf '\n'; sleep 0.5

p "dsh 'dumpsys battery | grep -m1 level'"
dsh 'dumpsys battery | grep -m1 level'
printf '\n'; sleep 0.5

p "dsh 'exit 7'; echo exit=\$?"
dsh 'exit 7'; echo "exit=$?"
printf '\n'; sleep 0.8
