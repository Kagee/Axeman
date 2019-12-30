#! /bin/bash
FOLDER="$1"
for INPUT in $FOLDER/*.csv.gz; do
  zcat $INPUT;
  echo;
done | sort -n| uniq | pigz > ${FOLDER}${2}.total
