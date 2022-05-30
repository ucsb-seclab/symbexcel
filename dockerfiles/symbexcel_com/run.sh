samples=$(find /input/ -type f -name "*.bin")
rm -f /output/jobs

for s in $samples; do
  NAME=$(basename $s | sed 's/.bin//g')
  log="/output/${NAME}.output"
  echo "echo processing ${NAME}... && timeout 3600 /symbexcel/run.py --skip --com --delegations --default-handlers --file $s -d -t 3300 --log /output/${NAME}.log --simgr /output/${NAME}.simgr --cfg /output/${NAME}.cfg --iocs /output/${NAME}.iocs --models /output/${NAME}.models &> $log || echo ${NAME} >> /output/errored_jobs" >> /output/jobs
done

parallel --jobs 80% :::: /output/jobs &&
echo SUCCESS!
