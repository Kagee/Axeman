#! /bin/bash
JOB="$(head -n 1 jobs.list)"
sed -i '1d' jobs.list
if [ "x" == "x$JOB" ] ; then
  echo "No job found, quitting!"
  exit 1
fi
echo "My job is $JOB";
$JOB
