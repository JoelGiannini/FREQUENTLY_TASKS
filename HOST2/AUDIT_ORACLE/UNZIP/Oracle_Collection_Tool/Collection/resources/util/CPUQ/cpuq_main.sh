#!/bin/sh

current_dir=`pwd`
output_dir="${CT_TMP}/CPUQ"
log_dir="${CT_TMP}/logs"
source_dir="../resources/util/CPUQ"

if [ ! -d "$output_dir" ] ; then
	mkdir -p "$output_dir" 
fi

if [ ! -d "$log_dir" ] ; then
	mkdir "$log_dir"
fi

cd $source_dir
chmod +x ct_cpuq.sh
./ct_cpuq.sh "${output_dir}" 

cd $output_dir
grep 'CPUQ: CT-[0-9][0-9][0-9][0-9][0-9]: WARNING:' *-ct_cpuq.txt  >$log_dir/CPUQ_warnings.log
grep 'CPUQ: CT-[0-9][0-9][0-9][0-9][0-9]: ERROR:' *-ct_cpuq.txt  >$log_dir/CPUQ_errors.log
grep 'Machine Name=' *-ct_cpuq.txt | sed 's/Machine Name=/CPUQ: CT-01000: COLLECTED: Machine Name: /g' >$log_dir/CPUQ_collected.log


for log in `ls $log_dir/CPUQ_*.log`
do
if [ ! -s $log ]; then
	rm -f $log
fi
done 

cd "$current_dir"