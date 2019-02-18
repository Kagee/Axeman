#! /bin/bash
find ./output -name '*metadata*' -exec bash -c 'python3.6 simple.py -n -c "$(dirname {})"' \; 2>&1 | grep -E 'length: |Last log update: |To continue: '
