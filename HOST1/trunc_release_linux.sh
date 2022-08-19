SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes -o ConnectTimeout=5"
V_server=$1
OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}' `
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}' `
STATUS="Online"
	if [[  $OS == "Linux" ]];
	then
	echo "$RELEASE"| sed  "s/_Enterprise_Linux_Server_release_/_/g"
	fi

