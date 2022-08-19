#!/usr/bin/ksh
if [[ ` ls -ltr /tmp | grep pasos.txt` != "" ]] ; then
 echo > /tmp/pasos.txt
fi

for M in `ls -ltr /sys/class/fc_host | awk '{print $9}'| sed '1d'`; do
	HOSTS=`echo $M |sed 's/host//g'`
	echo $HOSTS >> /tmp/pasos.txt
done

for X in ` pvs | grep "/dev" | awk '{ print $1}'`; do 
AUX=`echo $X |awk '{print $4}' FS="/"`
	if [[ $AUX == "" ]] ; then
	HDISK=`echo $X |awk '{print $3}' FS="/"`
	else
	HDISK=`echo $X |awk '{print $4}' FS="/"`
	
	VG=`pvdisplay $X | grep -i vg | awk '{print $3}'`
	if [[ $VG == "" ]] ; then
	VG="None"
	TIPOFS=` pvs | grep -w $X | awk '{print $2}'`
        PSIZE=` pvs | grep -w $X | awk '{print $4}'`
	PFREE=` pvs | grep -w $X | awk '{print $5}'`
	else
	TIPOFS=` pvs | grep -w $X | awk '{print $3}'`
	PSIZE=` pvs | grep -w $X | awk '{print $5}'`
	PFREE=` pvs | grep -w $X | awk '{print $6}'`
        fi
	
	fi
		if [[ ` multipath -l ${HDISK}| grep ${HDISK}` == ` multipath -l ${HDISK}| grep -w ${HDISK} | grep -i failed` || ` multipath -l ${HDISK}| grep -w ${HDISK}` == "" ]] ; then
		LUNID="DISCO_INTERNO"
		STORAGE="N/A"
		echo "" > /tmp/multipath.txt
		else
		LUNID=` multipath -l ${HDISK}| grep -w ${HDISK} | awk '{print $2}'|sed -e 's/(//g'| sed -e 's/)//g'`
		STORAGE=` multipath -l ${HDISK}| grep -w ${HDISK}| awk '{print $4}'`
			for Y in ` multipath -l ${HDISK} | sed '1,3d' | awk '{print $2}' | grep -v "policy=" | grep -v 'round-robin'`; do 
			CUT=`echo ${Y:0:1}` 
		
	if [[ $CUT == `cat /tmp/pasos.txt | grep $CUT` ]] ; then
		WWPN=`cat /sys/class/fc_host/host$CUT/port_name`
		EST_WWPN=`cat /sys/class/fc_host/host$CUT/port_state`
		MULTIPATH=` multipath -l ${HDISK} | grep $Y |awk '{print $3}'`
		echo $WWPN":"$EST_WWPN":"$MULTIPATH >> /tmp/multipath.txt
	fi

			done

		fi
       
	echo "${X} ${VG} ${TIPOFS} ${PSIZE} ${PFREE} ${LUNID} ${STORAGE} "`cat /tmp/multipath.txt | awk '{print}' ORS='|'|sed -e 's/.$//'`
	rm /tmp/multipath.txt
done

