#!/bin/bash
case "$1" in
    "next0")
        1>&2 echo "[INFO] Running < 1k bash-loop ...";
        bash <(./todo.sh | grep -v J | grep -Pv ',.*,' | grep simple)
        ;;
    "next2")
        1>&2 echo "[INFO] Running next job avaliable job > 1,000,000...";
        # return code 50 = this job was already running
        ./todo.sh | grep -v J | grep -P ',.*,' | grep simple | sort -k9 -n | \
          cut -d '#' -f 1 | while read -r JOB; do
            $JOB
          if [ $? -ne 50 ]; then
            1>&2 echo "[INFO] Return code was 1, job finished!";
            exit 1
          else
            1>&2 echo "[INFO] Job was already running, going for next ...";
          fi
        done;
        ;;
    "next1")
        1>&2 echo "[INFO] Running next job avaliable job > 1,000,000...";
        # return code 50 = this job was already running
        ./todo.sh | grep -v J | grep , | grep -Pv ',.*,' | grep simple | sort -k9 -n | \
          cut -d '#' -f 1 | while read -r JOB; do
            $JOB
          if [ $? -ne 50 ]; then
            1>&2 echo "[INFO] Return code was 1, job finished!";
            exit 1
          else
            1>&2 echo "[INFO] Job was already running, going for next ...";
          fi
        done;
        ;;
    *)
        1>&2 echo "[ERROR] Unknown option $1";
        exit 1;;
esac
