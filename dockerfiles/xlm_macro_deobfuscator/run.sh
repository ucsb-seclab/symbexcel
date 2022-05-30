samples=$(find /input/ -type f -name "*.bin")
rm -f /output/jobs

for s in $samples; do
  log="/output/$(basename $s | sed 's/.bin/.log/g')"
  echo "xlmdeobfuscator --file $s &> $log" >> /output/jobs
done

parallel --jobs 80% :::: /output/jobs
echo SUCCESS!
