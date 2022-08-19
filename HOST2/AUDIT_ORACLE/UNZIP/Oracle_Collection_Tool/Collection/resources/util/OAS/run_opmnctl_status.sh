#!/bin/sh
SCRIPT_VERSION="19.1($CT_BUILD_VERSION)"

setAlias() {
	unalias -a
	 
	cmd_list="printf
	echo
	touch
	cat
	more
	grep
	egrep
	cut
	find
	uname
	awk
	sed
	sort
	uniq
	expr
	cksum
	ps
	rm
	mkdir
	mv
	ls
	clear
	"
	 
	path_list="/bin/
	/usr/bin/"
	 
	alias_not_found="" 
	for c in $cmd_list
	do
		alias_flag=0
		 
		for p in $path_list
		  do 
		   if [ -x ${p}${c} ];
		   then
						alias ${c}=${p}${c}
						alias_flag=1
						break
		  fi
		  done    
		if [ $alias_flag -eq 0 ] ; then
		   if [ -z  "${alias_not_found}" ]; then
			  alias_not_found=$c
		   else       
			 alias_not_found=${alias_not_found},$c
		   fi            
		 fi
	done
	
	if [ -n "${alias_not_found}" ]; then 
	  $ECHO "OPMN: CT-00000: ERROR: \n${alias_not_found} utility(ies) not found. Please contact your assigned consultant."
	  exit 600
	fi
	#alias
}

echo_print() {
  #IFS=" " command 
  eval 'printf "%b\n" "$*"'
}

ECHO="echo_print"
setAlias

$ECHO "Starting run_opmnctl_status.sh script"
MACHINE_NAME=`uname -n`
CT_TEMPFILE=`ls -Art $CT_TMP/logs | grep CTfiles | tail -1`
if [ ! -d "${CT_TMP}/FMW" ] ; then
	mkdir -p "${CT_TMP}/FMW" 
fi	
CT_OPMN_OUT_FILE=$CT_TMP/FMW/${MACHINE_NAME}-opmn_output.txt
HM_NO=0
$ECHO "SCRIPT_VERSION = $SCRIPT_VERSION" > $CT_OPMN_OUT_FILE
$ECHO "=============================================================================" >> $CT_OPMN_OUT_FILE
for LOC in `cat $CT_TMP/logs/$CT_TEMPFILE | grep "bin/opmnctl" | grep -v "opmnctl.tmp"`
do
	HM_NO=`expr $HM_NO + 1`;
	$ECHO "Home$HM_NO:  Oracle Home = $LOC" | sed "s/\/opmn\/bin\/opmnctl//g" | sed "s/\/bin\/opmnctl//g" >> $CT_OPMN_OUT_FILE
	$ECHO "----------------" >> $CT_OPMN_OUT_FILE
	$LOC status >> $CT_OPMN_OUT_FILE 2>&1
	$ECHO "=============================================================================" >> $CT_OPMN_OUT_FILE
done
