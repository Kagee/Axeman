#! python3

import sys # exit codes and stdout
import glob # listing files
import gzip # gzip decompression and compression
import lzma # xz compression
import os # deleting files

if len(sys.argv) != 2:
    print("Expects one argument, folder with files to merge", file=sys.stderr)
    sys.exit(2)

folder = sys.argv[1]

startat = 0
j = startat
if len(sys.argv) == 3:
    j = int(sys.argv[2])
    startat = j

print(f"Starting at {j}:", file=sys.stderr)

inputfiles = sorted(glob.glob(folder + '/*.csv.gz') + glob.glob(folder + '/*.csv.xz'))
outfile = folder + ".no.list.xz"

with lzma.open(outfile, "w") as xzno:
    for gz in inputfiles:
        #print(gz)
        if gz.endswith(".gz"):
            f = gzip.open(gz, mode='rt')
        else:
            f = lzma.open(gz, mode='rt')
        for line in f:
            parts = line.split(';')
            num = int(parts[0])
            if j == num:
                if '.no' in parts[1]:
                    words = parts[1].strip().split(' ')
                    for word in words:
                        if word.endswith('.no'):
                            xzno.write((word + '\n').encode("utf-8"))
                j += 1
            elif j < num:
                    print(f"Error at {gz}:", file=sys.stderr)
                    print(f"Expected {j}, got {line.split(';')[0]}", file=sys.stderr)
                    break
            #else: if num if less than last j we saw, we just ignore it
# After with, so we close the file before moving if
final = f"{folder}-{startat:011}-{j-1:011}.no.csv.xz"
print(f"Finished for now, writing to {final}:", file=sys.stderr)
os.rename(outfile, final)
