#!/bin/bash -e

if [[ -z "$bucket" ]] ; then
  echo "bucket not set. Aborting"
  exit 1
fi

sleep_time=20

for f in `cat list` ; do
    echo $f
    sed s/OBJECT/$f/g requeue-event.json | sed s/BUCKET/$bucket/g > $f.invoke.json
    aws lambda invoke --function-name pht-prowler-process-finding-file \
        --cli-binary-format raw-in-base64-out \
        --invocation-type RequestResponse \
        --cli-read-timeout 0 \
        --payload file://$f.invoke.json outfile
    rm $f.invoke.json
    echo sleeping $sleep_time sec
    sleep $sleep_time
done