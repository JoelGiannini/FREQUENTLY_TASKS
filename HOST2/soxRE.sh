i=$1
OS=$2

if [ "$OS" == "Linux" ];
then
        if [[ `ssh -q $i "sudo cat /etc/redhat-release | grep 8.*"`  == "" ]]; then
                        ssh -q $i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
						   scp -q /home/ibmunx/JOEL/sox_tasa_linux_v2.5.sh $i:/SOX
                        ssh -q $i "sudo chmod +x /SOX/sox_tasa_linux_v2.5.sh"
                        #ssh -q $i "sudo nohup /SOX/sox_tasa_linux_v2.5.sh -i &"
        elif [[ `ssh -q $i "sudo cat /etc/redhat-release | grep [5-7].*"`  == "" ]]; then
                        ssh -q $i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
						   scp -q /home/ibmunx/JOEL/sox_tasa_linux_rhel8_v3.1.sh $i:/SOX
                        ssh -q $i "sudo chmod +x /SOX/sox_tasa_linux_rhel8_v3.1.sh"
                        ssh -q $i "sudo nohup /SOX/sox_tasa_linux_rhel8_v3.1.sh -i &"
        elif [[ `ssh -q $i "cat /etc/os-release 2>/dev/null" | grep PRETTY_NAME` != "" ]]; then
        echo "Es SUSE"
        elif [[ `ssh -q $i "cat /etc/oracle-release 2>/dev/null" |awk '{print $1}' |tr -d "\015"` == "Oracle" ]]; then
        echo "Es Oracle linux"
        elif [[ `ssh -q $i "cat /etc/lsb-release 2>/dev/null" | grep  -i Description` != "" ]]; then
        echo "Es ubuntu"
fi

elif [ "$OS" == "AIX" ]; then
                ssh -q $i "sudo mkdir /SOX 2>/dev/null && sudo chmod 7777 /SOX"
				  scp -q /home/ibmunx/JOEL/sox_remediacion_AIX_v2.1.sh $i:/SOX
                ssh -q $i "sudo chmod +x /SOX/sox_remediacion_AIX_v2.1.sh"
                #ssh -q $i "sudo nohup /SOX/sox_remediacion_AIX_v2.1.sh &"


elif [ "$OS" == "SunOS" ]; then
ssh -q $i "sudo touch /tmp/prueba_ok"
#ssh -q $i "sudo nohup /net/recover10/vol1/Sun/Install/all_install_20_SOX_v3.ksh &"

fi
