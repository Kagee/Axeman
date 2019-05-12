#!/bin/bash
if [ "x--fast" != "x$1" ]; then
  echo "[INFO] Generating status.txt"
  ./simple.py -b | tee status.txt | grep -v -E ' OK '
else
 cat status.txt
fi
echo ""
echo "[INFO] TODOs:"
grep -v -E ' OK |(J)' status.txt | while read LINE; do
  LOG="$(echo "$LINE" | cut -d' ' -f 1)"
  echo "$LINE" | grep 'missing:' | sed -e "s/\(missing:[^ ]*\)/\n\1\n/g" | grep missing: | \
    while read MISSING; do 
      START="$(echo "$MISSING" | cut -d: -f2)"; 
      END="$(echo "$START" | cut -d- -f2)"; 
      START="$(echo "$START" | cut -d- -f1)"; 
      echo "./simple.py -n -u $LOG -s $START -e $END"; 
    done;
  END="$(echo "$LINE" | grep 'missing (end)' | sed -e 's/.*missing (end):\([0-9]*\)-\([0-9]*\).*/\1/';)"
  DIFF="$(echo "$LINE" | grep 'missing (end)' | sed -e 's/.*missing (end):[0-9]*-[0-9]* (\([0-9,]*\)).*/\1/';)"
  if [ ! -z "$END" ]; then
    END="$(echo "$END - 100" | bc)"
    echo "./simple.py -n -u $LOG -s $END # diff: $DIFF"
  fi
done;
