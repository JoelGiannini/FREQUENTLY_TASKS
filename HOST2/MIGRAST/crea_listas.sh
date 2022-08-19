#!/usr/bin/bash
SCP="sudo scp -q"
SERVER="$1"
SSH="sudo ssh -o ConnectTimeout=5 -o BatchMode=yes -q"
LISTAO="${SERVER}_origen.txt"
LISTAD="${SERVER}_destino.txt"

$SSH $SERVER "mkdir -p /root/migra"
$SCP releva_linux_sat.sh $SERVER:/root/migra/releva_linux_sat.sh
$SSH $SERVER "chmod +x /root/migra/releva_linux_sat.sh"
$SSH $SERVER "for M in `ls -ltr /sys/class/fc_host | awk '{print $9}'| sed '1d'`; do
        HOSTS=`echo $M |sed 's/host//g'`
        echo "- - -" > /sys/class/scsi_host/host${HOSTS}/scan
done"
#$SSH $SERVER "sh releva_linux_sat.sh 2> /dev/null"|grep -i "HP" |grep -i "virtual"|grep -v None >$LISTA
$SSH $SERVER "sh releva_linux_sat.sh 2> /dev/null"|grep "HP"|grep -v None >$LISTAO
$SSH $SERVER "sh releva_linux_sat.sh 2> /dev/null"|grep -E 'HUAWEI|IBM|EMC CLARiiON'|grep None >$LISTAD
~                                                                                                        
