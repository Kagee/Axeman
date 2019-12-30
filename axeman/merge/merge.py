#! python3

import sys
import glob
import gzip
import lzma

if len(sys.argv) != 2:
    print("Expects one argument, folder with files to merge", file=sys.stderr)
    sys.exit(2)

folder = sys.argv[1]

j = 0;
with lzma.open("file.xz", "w") as xz, gzip.open("file.gzip", "w") as gz, open("file", "w") as out:
  for gz in sorted(glob.iglob(folder + '/*.csv.gz')):
    f = gzip.open(gz, mode='rt')
    for line in f:
        if j == int(line.split(';')[0]):
            print(line.strip())
            out.write(line.strip() + '\n')
            j += 1
        else:
            if j < int(line.split(';')[0]):
                print(f"Expected {j}, got {line.split(';')[0]}", file=sys.stderr)
                sys.exit(3)
print(f"Output file is 00000000000-{j-1:011}.csv.xxx", file=sys.stderr)
