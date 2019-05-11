#! /bin/bash
#find ./output -name '*metadata*' -exec bash -c 'python3.6 simple.py -n -c "$(dirname {}); echo "";"' \; 2>&1 | grep -E 'length: |Last log update: |To continue: '
./simple.py -a | sort -g > estimates.txt; reset; cat estimates.txt
cat estimates.txt | grep -v '(J)' | awk '/^[1-9][0-9]*\t[1-9]{4}/{ print $4 }' | xargs -L 1 -- ./simple.py -n -c 2>&1 | grep -E "length:|Last log|To continue"
