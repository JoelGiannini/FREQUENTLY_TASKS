SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes -o ConnectTimeout=5"
SCP="sudo /usr/bin/scp -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no"
i=$1
OS=$2

if [ "$OS" == "Linux" ];
then
	if [[ `${SSH} ibmunx@$i "sudo cat /etc/redhat-release | grep 8.*"`  == "" ]]; then
			${SSH} ibmunx@$i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
			$SCP /home/ibmunx/JOEL/PRUEBA/sox_tasa_linux_v2.5.sh ibmunx@$i:/SOX
			${SSH} ibmunx@$i "sudo chmod +x /SOX/sox_tasa_linux_v2.5.sh"
			#${SSH} ibmunx@$i "sudo nohup /SOX/sox_tasa_linux_v2.5.sh -i &"
	elif [[ `${SSH} ibmunx@$i "sudo cat /etc/redhat-release | grep [5-7].*"`  == "" ]]; then
			${SSH} ibmunx@$i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
 			$SCP /home/ibmunx/JOEL/PRUEBA/sox_tasa_linux_rhel8_v3.1.sh ibmunx@$i:/SOX
                        ${SSH} ibmunx@$i "sudo chmod +x /SOX/sox_tasa_linux_rhel8_v3.1.sh"
                        #${SSH} ibmunx@$i "sudo nohup /SOX/sox_tasa_linux_rhel8_v3.1.sh -i &"
	elif [[ `$SSH ibmunx@$1 "cat /etc/os-release 2>/dev/null" | grep PRETTY_NAME` != "" ]]; then
	echo "Es SUSE"
	elif [[ `$SSH ibmunx@$1 "cat /etc/oracle-release 2>/dev/null" |awk '{print $1}' |tr -d "\015"` == "Oracle" ]]; then
	echo "Es Oracle linux"
	elif [[ `$SSH ibmunx@$1 "cat /etc/lsb-release 2>/dev/null" | grep  -i Description` != "" ]]; then
	echo "Es ubuntu"
fi

elif [ "$OS" == "AIX" ]; then
		${SSH} ibmunx@$i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
		$SCP /home/ibmunx/JOEL/PRUEBA/sox_remediacion_AIX_v2.1.sh ibmunx@$i:/SOX
                ${SSH} ibmunx@$i "sudo chmod +x /SOX/sox_remediacion_AIX_v2.1.sh"
                #${SSH} ibmunx@$i "sudo nohup /SOX/sox_remediacion_AIX_v2.1.sh &"


elif [ "$OS" == "SunOS" ]; then
${SSH} ibmunx@$i "sudo touch /tmp/prueba_ok"
#${SSH} ibmunx@$i "sudo nohup /net/recover10/vol1/Sun/Install/all_install_20_SOX_v3.ksh &"

fi
