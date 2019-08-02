#!/bin/bash
function update-status() {
  ./simple.py -b | tee status.txt.tmp | grep -v -E ' OK '
  mv status.txt.tmp status.txt
}
MAXAGE=360
case "$1" in
    "")
        if [[ $(find "status.txt" -cmin +$MAXAGE -print) ]] || [ ! -f "status.txt" ]; then
          1>&2 echo "[INFO] status.txt older than $MAXAGE minutes, updating ...";
          update-status
        else
          1>&2 echo "[INFO] status.txt younger than $MAXAGE minutes, re-using";
        fi;;
    "--no-update"|"--fast")
        1>&2 echo "[INFO] Forcing re-use of status.txt";;
    "--update")
        1>&2 echo "[INFO] Forcing update of status.txt";
        update-status;;
    *)
        1>&2 echo "[ERROR] Unknown option $1";
        exit 1;;
esac
echo ""
echo "[INFO] TODOs:"
grep -v -E ' OK ' status.txt | while read -r LINE; do
  LOG="$(echo "$LINE" | cut -d' ' -f 1)"
  echo "$LINE" | grep 'missing:' | sed -e "s/\(missing:[^ ]*\)/\n\1\n/g" | grep missing: | \
    while read -r MISSING; do
      START="$(echo "$MISSING" | cut -d: -f2)";
      END="$(echo "$START" | cut -d- -f2)";
      START="$(echo "$START" | cut -d- -f1)";
      echo "./simple.py -n -u $LOG -s $START -e $END # $(echo "$END - $START" |bc)";
    done;
  END="$(echo "$LINE" | grep 'missing (end)' | sed -e 's/.*missing (end):\([0-9]*\)-\([0-9]*\).*/\1/';)"
  DIFF="$(echo "$LINE" | grep 'missing (end)' | sed -e 's/.*missing (end):[0-9]*-[0-9]* (\([0-9,]*\)).*/\1/';)"
  if [ ! -z "$END" ]; then
    END="$(echo "$END - 100" | bc)"
    J=" $(echo "$LINE" | grep -o '(J)')"
    echo "./simple.py -n -u $LOG -s $END # diff: ${DIFF}${J}"
  fi
done;
