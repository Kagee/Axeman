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
with lzma.open(filename + ".csv.xz", "w") as xzo, gzip.open(filename + ".csv.gz", "w") as gzo, open(filename, "w") as out:
    # 1k files at a time
    inputfiles = sorted(glob.glob(folder + '/*.csv.gz') + glob.glob(folder + '/*.csv.xz'))[:1000]
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
                out.write(st + '\n')
                #xzo.write((st + '\n').encode("utf-8"))
                gzo.write((st + '\n').encode("utf-8"))
                j += 1
            else:
                if j < int(line.split(';')[0]):
                    print(f"Error at {gz}:", file=sys.stderr)
                    print(f"Expected {j}, got {line.split(';')[0]}", file=sys.stderr)
                    os.unlink(filename)
                    os.unlink(filename + ".csv.xz")
                    os.unlink(filename + ".csv.gz")
                    sys.exit(3)
    for fin in inputfiles:
         os.unlink(fin)
    print(f"Moving {filename + '.csv.gz'} to {folder}/" + f'/00000000000-{j-1:011}.csv.gz', file=sys.stderr)
    os.rename(filename + ".csv.gz", folder + '/' + f"00000000000-{j-1:011}.csv.gz")
