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

filename = "combined_" + folder

j = 0;
mincombine = 10000
inputfiles = sorted(glob.glob(folder + '/*.csv.gz') + glob.glob(folder + '/*.csv.xz'))[:mincombine]
if len(inputfiles) < 10:
    print(f"Less than {10} inputfiles, not combining.", file=sys.stderr)
    sys.exit(2)

with lzma.open(filename + ".csv.xz", "w") as xzo:
    for gz in inputfiles:
        #print(gz)
        if gz.endswith(".gz"):
            f = gzip.open(gz, mode='rt')
        else:
            f = lzma.open(gz, mode='rt')
        for line in f:
            if j == int(line.split(';')[0]):
                st = line.strip()
                #print(st)
                xzo.write((st + '\n').encode("utf-8"))
                j += 1
            else:
                if j < int(line.split(';')[0]):
                    print(f"Error at {gz}:", file=sys.stderr)
                    print(f"Expected {j}, got {line.split(';')[0]}", file=sys.stderr)
                    os.unlink(filename + ".csv.xz")
                    sys.exit(3)
for fin in inputfiles:
     os.unlink(fin)
print(f"Moving {filename + '.csv.xz'} to {folder}/" + f'00000000000-{j-1:011}.csv.xz', file=sys.stderr)
os.rename(filename + ".csv.xz", folder + '/' + f"00000000000-{j-1:011}.csv.xz")
