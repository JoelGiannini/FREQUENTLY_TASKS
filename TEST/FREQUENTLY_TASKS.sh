#######################################
#     Desarrollador: Joel Giannini    #
#     FREQUENTLY_TASKS                #
#     Tareas Frecuentes               #
#######################################
#Declaracion de variables
h=`date "+%H" `
m=`date "+%M" `
s=`date "+%S" `
dia=`date "+%d" `
mes=`date "+%m" `
anio=`date "+%Y" ` 
SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes -o ConnectTimeout=5"
SCP="sudo /usr/bin/scp -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no"
V_red='\e[0;31m'
V_orange='\e[1;31m'
V_white='\e[1;37m'
V_yellow='\e[1;33m'
V_blue='\e[0;34m'
V_cyan='\e[0;36m'
V_green='\e[0;32m'
NC='\e[0m' # No Color 

##############
#Funcion menu#
##############
menu(){
while :
do
clear
#ACA VA EL MENU#

echo -e "${V_orange}⠀⠀⠀⠀⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣤${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⣿⡇⠀⣠⣶⠖⢲⣶⠀⠀⠀⣰⣶⢰⣶⣶⠾⢿⣶⡄⠀⣠⣶⡿⠷⣦⣿⡇⢰⣶⣶⠾⠷⣶⣆⠀⠀⠀⣶⡶⢸⣿${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⣿⣧⣾⡟⠁⠀⠈⣿⣇⠀⢠⣿⠇⢸⣿⠃⠀⠀⣿⣿⢰⣿⡇⠀⠀⠈⣿⡇⢸⣿⡇⠀⠀⠸⣿⡄⠀⢰⣿⠃⢸⣿${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⣿⡇⠈⢿⣧⡀⠀⠸⣿⡀⣾⡟⠀⢸⣿⠀⠀⠀⣿⣿⠘⣿⣇⠀⠀⢀⣿⡇⢸⣿⡇⠀⠀⠀⢻⣷⢀⣿⡏⠀⢸⣿${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⠿⠇⠀⠀⠻⠿⠄⠀⠻⢷⣿⠁⠀⠸⠿⠀⠀⠀⠿⠿⠀⠙⠿⢷⠾⠟⠿⠇⠸⠿⠃⠀⠀⠀⠈⠿⣿⡿⠀⠀⠸⠿${NC}"⠀⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⠃⠀⠀⠀⠀${NC}"⠀⠀⠀
echo -e "${V_orange}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠋⠀⠀⠀⠀⠀${NC}"⠀
echo -e "${V_white}                            By Joel Giannini.  ${NC}"

echo ""
echo "--------------------------------------------------"
echo " * * * * * * * * * opciónes * * * * * * * * * * "
echo "--------------------------------------------------"
echo ""
echo -e "[${V_yellow}1${NC}] Crear archivo de configuración de red"
echo -e "[${V_yellow}2${NC}] Sacar reporte ADU Report"
echo -e "[${V_yellow}3${NC}] Verificar File systems"
echo -e "[${V_yellow}4${NC}] Inventario"
echo -e "[${V_yellow}5${NC}] Ejecutar reporte de auditoria de Oracle"
echo -e "[${V_yellow}6${NC}] Generar caso de Hardware"
echo -e "[${V_yellow}7${NC}] Configurar multipath alies"
echo -e "[${V_yellow}8${NC}] Aplicar SOX a servidor"
echo -e "[${V_yellow}9${NC}] Instalar Elasticsearch"
echo -e "[${V_yellow}10${NC}] Salir"
echo ""
echo "--------------------------------------------------"
echo ""
echo -e "Elegi una opción [ ${V_yellow}1${NC}-${V_yellow}10${NC} ]:"
read yourch
while [ $yourch -lt 1 ] || [ $yourch -gt 10 ]
do
echo "opción erronea, ingresar numero de opción entre [1-10]:"
read yourch
done

case $yourch in
1) F_conf_red ;;
2) F_adu_report ;;
3) F_fs_verif ;;
4) F_inventario ;;
5) F_ora_audit_report ;;
6) F_gen_caso ;;
7) F_conf_multipath_alies ;;
8) F_sox ;;
9) F_install_elastic ;;
10) echo -e "${V_cyan}Hasta la vista baby!!!${NC}" ; echo "" ; echo "" ; exit 0 ;;
esac
done
}



########################################
# Funcion crear archivo de conf de red #
########################################
F_conf_red(){
clear

echo -e "${V_yellow}1${NC}) Crear archivo de Conf de RED"
echo -e "${V_yellow}2${NC}) Volver al menu principal"
read aux

clear

while [ $aux -lt 1 ] || [ $aux -gt 2 ]
do
echo "valor incorrecto ingrese la opción correcta"
read aux
done


while [[  $aux == "1" ]] || [[  $aux == "2" ]]
do
if [ $aux -eq 1 ] ; then

echo "Ingrese servidor en el cual se va a configurar la RED"
read V_server
clear
echo -e "${V_cyan}Configuration de las interfaces de RED en el server $V_server${NC}"
echo ""
${SSH} ibmunx@$V_server "sudo /sbin/ifconfig -a |grep -v RX| grep -v TX | grep -v lo: | grep -vw inet6 | grep -v ether | grep -v loop| grep -v 127.0.0.1 | grep -v collisions |grep -v 'UP LOOPBACK'| grep -v 'UP BROADCAST' | grep -v Interrupt | grep -v 'lo        Link'"

echo -e "ingresar el nombre del archivo de configuracion de Red que se va a configurar.${V_red} NO PONER EL ifcfg- solo el nombre del DEVICE ${NC}"
read V_name_arch
echo "ingresar DEVICE" 
read V_dev
echo "ingresar IP" 
read V_ip
echo "ingreser NETMASK" 
read V_mask

${SSH} ibmunx@$V_server "echo "DEVICE=$V_dev" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"
${SSH} ibmunx@$V_server "echo "ONBOOT=yes" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"
${SSH} ibmunx@$V_server "echo "USERCTL=no" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"
${SSH} ibmunx@$V_server "echo "BOOTPROTO=none" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"
${SSH} ibmunx@$V_server "echo "IPADDR=$V_ip" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"
${SSH} ibmunx@$V_server "echo "NETMASK =$V_mask" | sudo tee --append /etc/sysconfig/network-scripts/ifcfg-$V_name_arch"

echo "¿Desea reiniciar el servicio de RED en el server V_server?"
echo -e "${V_yellow}1${NC}) Si"
echo -e "${V_yellow}2${NC}) No"
read aux
if [ $aux -eq 1 ] ; then
echo "NADA"
fi
else
menu

fi
echo -e "${V_yellow}1${NC}) Crear otro archivo de Conf de RED"
echo -e "${V_yellow}2${NC}) Volver al menu principal"
read aux

done

}

########################################
# Funcion ADU Report                   #
########################################
F_adu_report(){
clear

echo "Ingrese servidor en el cual se va a correr el ADU Report"
read V_server
ssh_test;
ping_test;
clear
if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi

if [[  $SSH_TEST == "ERROR" ]];
then
	
OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}' `
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}' `
	if [ "$OS" != "Linux" ]
 		then

			echo "Esta opcion es valida solo para servidores Red—Hat."
			echo "El servidor que ingresaste es:"
			echo -e "${V_cyan} $V_server $OS $RELEASE ${NC}"


			echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done
	else
		$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/aduRE.sh $V_server >/dev/null 2>&1"
		$SCP ibmunx@apsatellitep03:/home/ibmunx/JOEL/ADU_REPORT/REPORTES/* /home/ibmunx/JOEL/ADU_REPORT/REPORTES
		$SSH ibmunx@apsatellitep03 "sudo rm -f /home/ibmunx/JOEL/ADU_REPORT/REPORTES/*"
		echo "Se dejo el reporte en /home/ibmunx/JOEL/ADU_REPORT/REPORTES:"
		echo ""
		echo -e "${V_cyan}Archivo:${NC}"
		sudo ls -ltr /home/ibmunx/JOEL/ADU_REPORT/REPORTES | grep $V_server;
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

	fi
	
fi

test_os;

if [ "$OS" != "Linux" ]
 		then

			echo "Esta opcion es valida solo para servidores Red—Hat."
			echo "El servidor que ingresaste es:"
			echo -e "${V_cyan} $V_server $OS $RELEASE ${NC}"


			echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done
	else
		sudo /home/ibmunx/JOEL/ADU_REPORT/adu_report.sh $V_server > /dev/null 2>&1;
	echo "Se dejo el reporte en /home/ibmunx/JOEL/ADU_REPORT/REPORTES:"
	echo ""
	echo -e "${V_cyan}Archivo:${NC}"
	sudo ls -ltr /home/ibmunx/JOEL/ADU_REPORT/REPORTES | grep $V_server;
	echo ""			
			echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

	fi


}

########################################
# Funcion Verificar Filesystems        #
########################################
F_fs_verif(){
clear
echo -e "${V_cyan}################################################################################${NC}"
echo -e "${V_cyan}# Verificacion de Filesystems                                                  #${NC}"
echo -e "${V_cyan}################################################################################${NC}"
echo ""
echo "Ingrese servidor en el cual se va a verificar los Filesystem:"
echo -e "${V_red}IMPORTANTE POR EL MOMENTO SOLO SE VERIFICAN SERVIDORES RED-HAT y AIX${NC}"
read V_server
ssh_test;
ping_test;

if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi


while [[  $SSH_TEST == "ERROR" ]]
do
OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}' `
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}' `
clear
	echo -e "${V_cyan}$V_server${NC}"
	echo "File-systems:"
$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/fs_verifRE.sh $V_server $OS"

echo -e "${V_yellow}1${NC}) Volver al menu principal:"
read aux

clear

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu
done

done

clear
test_os;
if [ "$OS" == "AIX" ]
 	then
	echo -e "${V_cyan}$V_server${NC}"
	echo "File-systems:"
	F_fs_aix;
	echo -e "${V_yellow}1${NC}) Volver al menu principal:"
	read aux
	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done
	while [[  $aux == "1" ]]
	do
	menu
	done

	fi


if [[  $OS == "Linux" ]]; then
	echo -e "${V_cyan}$V_server${NC}"
	echo "File-systems:"
${SSH} ibmunx@$V_server "sudo cat /etc/fstab | grep -v '#' | grep -vw devpts| grep -vw sysfs | grep -vw proc |grep -vw swap |sudo sed '/^ *$/d'"| awk '{print $2}' | sudo tee /tmp/fs1.txt


		for i in `sudo cat /tmp/fs1.txt`; do 
		V_df=`${SSH} ibmunx@$V_server "sudo df -k "|grep -w $i`
			if [[ `${SSH} ibmunx@$V_server "sudo df -k "|grep -w $i` == "" ]] ; then
				echo "El filesystem $i no se encuentra montado.";
				${SSH} ibmunx@$V_server "sudo mount -a"
				echo "Se monto el filesystem $i.";
				else
				echo "El filesystem $i se encuentra montado.";
				fi
		done
		if [[ `${SSH} ibmunx@$V_server "sudo cat /proc/mounts" |grep -P "\sro[\s,]"` == "" ]] ; then
		echo -e "${V_cyan}No hay Filesystems en Read-Only.${NC}";
		else
			echo -e "${V_red}Los siguientes filesystems estan en estado Read Only:${NC}"
			${SSH} ibmunx@$V_server "sudo cat /proc/mounts" | grep -P "\sro[\s,]"
		fi

		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux

		clear

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu
done
fi



}


########################################
# Funcion Inventario                   #
########################################
F_inventario(){
clear

echo -e "${V_cyan}################################################################################${NC}"
echo -e "${V_cyan}# Inventario                                                                   #${NC}"
echo -e "${V_cyan}################################################################################${NC}"
echo ""
echo -e "${V_yellow}1${NC}) Buscar servidor en el inventario."
echo -e "${V_yellow}2${NC}) Actualizar servidor en el inventario."
echo -e "${V_yellow}3${NC}) Dar de alta nuevo servidor en el inventario."
echo -e "${V_yellow}4${NC}) Dar de baja servidor en el inventario."
echo -e "${V_yellow}5${NC}) Volver al menu principal."

read aux

while [ $aux -lt 1 ] || [ $aux -gt 5 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

case $aux in
1) F_buscar_s ;;
2) F_update_s ;;
3) F_add_s ;;
4) F_delete_s;;
5) menu ;;
esac

}

########################################
# Funcion Buscar Servidor              #
########################################
F_buscar_s(){
clear

V_servidor="Servidor"
V_consola="Consola"
V_ip_prod="IP_Prod"
V_ubicacion="Ubicacion"
V_serial_id="Num_serie"
V_TIPO="Tipo"
echo "Ingrese servidor:"
read V_server

V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
V_tipo=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $6}'`
V_os="Sist_ope"
V_re="Release"
V_status="Status"
STATUS="Online"
ssh_test;
ping_test;
test_os;
clear


if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
   			then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			echo -e "¿Desea agregar al servidor ${V_red}$V_server${NC} al inventario?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux

		while [ $aux -lt 1 ] || [ $aux -gt 2 ] || [ $aux == ""]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
				if [ $aux -eq 1 ] ; then
				F_add_s;	
				else
				menu
				fi
fi

	if [[  $PING_TEST == "ERROR" ]];
	then
	echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
	echo -e "${V_yellow}1${NC}) Continuar con la busqueda del servidor ${V_red}$V_server${NC} en el inventario"
	echo -e "${V_yellow}2${NC}) Volver al menu principal"
	read aux

	clear

		while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "valor incorrecto ingrese la opción correcta"
			read aux
		done
		
		if [[  $aux == "1" ]]
		then

			STATUS="Offline"
			OS="##########"
			RELEASE="##########"
		else 
		menu;
		fi

	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

	echo ""
	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	read aux

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	menu;
	done
	fi


if [[ $SSH_TEST == "ERROR" ]];
then


OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
	
	if [[  $OS == "Linux" ]];
	then
	RELEASE=`sudo /home/ibmunx/JOEL/PRUEBA/trunc_release_linux.sh $V_server|tr -d "\015"`
	fi

	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

echo""
echo -e "${V_yelow}1${NC}) Volver al menu anterior."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

fi

	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

echo ""
echo -e "${V_yelow}1${NC}) Volver al menu anterior."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done


}

########################################
# Funcion update inventario            #
########################################
F_update_s(){
clear

V_servidor="Servidor"
V_consola="Consola"
V_ip_prod="IP_Prod"
V_ubicacion="Ubicacion"
V_serial_id="Num_serie"
V_TIPO="Tipo"
echo "Ingrese servidor:"
read V_server

V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
V_tipo=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $6}'`
V_os="Sist_ope"
V_re="Release"
V_status="Status"
STATUS="Online"
ssh_test;
ping_test;
test_os;
clear

if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
   			then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			echo -e "¿Desea agregar al servidor ${V_red}$V_server${NC} al inventario?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux

		while [ $aux -lt 1 ] || [ $aux -gt 2 ] || [ $aux == ""]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
				if [ $aux -eq 1 ] ; then
				F_add_s;	
				else
				menu
				fi
fi

if [[  $PING_TEST == "ERROR" ]];
	then
	echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
	echo -e "${V_yellow}1${NC}) Continuar con la actualizacion de campos en el inventario del servidor ${V_red}$V_server${NC}."
	echo -e "${V_yellow}2${NC}) Volver al menu principal"
	read aux

	clear

		while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "valor incorrecto ingrese la opción correcta"
			read aux
		done
		
		if [[  $aux == "1" ]]
		then

			STATUS="Offline"
			OS="##########"
			RELEASE="##########"
		else 
		menu;
		fi
fi
if [[ $SSH_TEST == "ERROR" ]];
then


OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
	
	if [[  $OS == "Linux" ]];
	then
	RELEASE=`sudo /home/ibmunx/JOEL/PRUEBA/trunc_release_linux.sh $V_server|tr -d "\015"`
	fi
fi

	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
echo ""
echo -e "${V_cyan}¿Que campo desea modificar?${NC}"
echo -e "${V_yelow}1${NC}) Servidor."
echo -e "${V_yelow}2${NC}) Consola."
echo -e "${V_yelow}3${NC}) Ip."
echo -e "${V_yelow}4${NC}) Ubicacion."
echo -e "${V_yelow}5${NC}) Serial Number."
echo -e "${V_yelow}6${NC}) Tipo."
echo -e "${V_yelow}7${NC}) Volver al menu anterior."

read aux

while [ $aux -lt 1 ] || [ $aux -gt 7 ]
do
echo "valor incorrecto ingrese la opción correcta"
read aux
done


while [[  $aux == "1" ]]
do
clear
echo "Ingrese nuevo valor para el campo Servidor:"
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv | awk -F':' '{print $1}'|tr -d "\015"`
sudo sed -i "${line} s/${V_serv}/${V_new}/g" /home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_serv=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
echo ""

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done

while [[  $aux == "2" ]]
do
clear
echo "Ingrese nuevo valor para el campo Consola:"
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv | awk -F':' '{print $1}'|tr -d "\015"`
sudo sed -i "${line} s/${V_con}/${V_new}/g" /home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_con=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
echo ""

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done

while [[  $aux == "3" ]]
do
clear
echo "Ingrese nuevo valor para el campo IP:"
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv | awk -F':' '{print $1}'|tr -d "\015"`
sudo sed -i "${line} s/${V_ip}/${V_new}/g" /home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_ip=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
echo ""

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done

while [[  $aux == "4" ]]
do
clear
echo "Ingrese nuevo valor para el campo ubicacion:"
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv | awk -F':' '{print $1}'|tr -d "\015"`
sudo sed -i "${line} s/${V_ubi}/${V_new}/g" /home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_ubi=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
echo ""

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done

while [[  $aux == "5" ]]
do
clear
echo "Ingrese nuevo Numero de serie"
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv| awk -F':' '{print $1}'|tr -d "\015"`
sudo sed -i "${line} s/${V_serial}/${V_new}/g" /home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_serial=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done

while [[  $aux == "6" ]]
do
clear
echo "Ingrese TIPO de servidor"
	echo ""	
	echo -e "${V_cyan}Tipos:${NC}"
	echo -e "${V_red}#######################################################${NC}"
	echo -e "${V_red}# LPAR VMware FISICO LDOM SOLARIS_CONTAINER HMC Other #${NC}"
	echo -e "${V_red}#######################################################${NC}"
	echo ""
read V_new
line=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -nw $V_serv | awk -F':' '{print $1}'|tr -d "\015"`
echo "$line"
read
sudo sed -i "${line} s/${V_tipo}/${V_new}/g"/home/ibmunx/JOEL/PRUEBA/Inventario.txt
V_tipo=$V_new
clear
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt

echo -e "${V_yelow}1${NC}) Volver al menu principal."
read aux

while [ $aux -lt 1 ] || [ $aux -gt 1 ]
do
echo "Valor incorrecto ingrese la opción correcta:"
read aux
done

while [[  $aux == "1" ]]
do
menu;
done

done


}

##########################################
# Funcion alta en inventario             #
##########################################
F_add_s(){
clear
V_servidor="Servidor"
V_consola="Consola"
V_ip_prod="IP_Prod"
V_ubicacion="Ubicacion"
V_serial_id="Num_serie"
V_TIPO="Tipo"
echo "Ingrese servidor:"
read V_server

V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
V_tipo=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $6}'`
V_os="Sist_ope"
V_re="Release"
V_status="Status"
STATUS="Online"
ssh_test;
ping_test;
test_os;
clear

if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` != "" ]]
then
   	

		if [[  $PING_TEST == "ERROR" ]];
		then
			echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
			echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} ya se encuentra en el inventario no hace falta agregarlo.${NC}"
			STATUS="Offline"
			OS="##########"
			RELEASE="##########"
		
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
			echo ""
			echo -e "${V_yelow}1${NC}) Volver al menu anterior."
			echo -e "${V_yelow}2${NC}) Volver al menu principal."
			read aux

			while [ $aux -lt 1 ] || [ $aux -gt 2 ]
			do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
			done

			while [[  $aux == "1" ]]
			do
			F_inventario;
			done

			while [[  $aux == "2" ]]
			do
			menu;
			done 
		
		

		fi

		if [[ $SSH_TEST == "ERROR" ]];
		then


			OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
			RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
	
		if [[  $OS == "Linux" ]];
		then
			RELEASE=`sudo /home/ibmunx/JOEL/PRUEBA/trunc_release_linux.sh $V_server|tr -d "\015"`
		fi
		
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

		
			echo ""
			echo -e "${V_yelow}1${NC}) Volver al menu anterior."
			echo -e "${V_yelow}2${NC}) Volver al menu principal."
			read aux

			while [ $aux -lt 1 ] || [ $aux -gt 2 ]
			do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
			done

			while [[  $aux == "1" ]]
			do
			F_inventario;
			done

			while [[  $aux == "2" ]]
			do
			menu;
			done 

		fi
		
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

		
			echo ""
			echo -e "${V_yelow}1${NC}) Volver al menu anterior."
			echo -e "${V_yelow}2${NC}) Volver al menu principal."
			read aux

			while [ $aux -lt 1 ] || [ $aux -gt 2 ]
			do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
			done

			while [[  $aux == "1" ]]
			do
			F_inventario;
			done

			while [[  $aux == "2" ]]
			do
			menu;
			done 		

fi

	


if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
	then
	
		if [[  $PING_TEST == "ERROR" ]];
		then


		echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
		echo -e "${V_yellow}1${NC}) Continuar con el alta del servidor ${V_red}$V_server${NC} en el inventario"
		echo -e "${V_yellow}2${NC}) Volver al menu principal"
		read aux

		clear

		while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "valor incorrecto ingrese la opción correcta"
			read aux
		done
		
		if [[  $aux == "1" ]]
		then

			STATUS="Offline"
			OS="##########"
			RELEASE="##########"
		else 
		menu;
		
		fi



		fi
	


	echo "Ingrese la consola correspondiente al servidor $V_servi, en caso de no tener presionar ENTER"
	read V_conso

	if [ "$V_conso" == "" ];
   	then
    V_conso="########"
	fi


	echo "Ingrese IP del server $V_server:"
	read V_ip_dir

	echo "Ingrese la ubicacion fisica del servidor $V_server, en caso de ser virtual ingresar el VCENTER:"
	read V_ubic
	
	if [ "$V_ubic" == "" ];
   	then
    V_sn="########"
  	fi
	
	echo "Ingrese el serial number correspondiente al servidor $V_server, en caso de no tener presionar ENTER"
	read V_sn

	if [ "$V_sn" == "" ];
   	then
    V_sn="########"
  	fi

	echo "Ingrese el TIPO de servidor correspondiente al  server $V_server, en caso de no tener presionar ENTER"
	echo ""
	echo -e "${V_cyan}Tipos:${NC}"
	echo -e "${V_red}#######################################################${NC}"
	echo -e "${V_red}# LPAR VMware FISICO LDOM SOLARIS_CONTAINER HMC Other #${NC}"
	echo -e "${V_red}#######################################################${NC}"
	echo ""
	read V_tp

	if [ "$V_tp" == "" ];
   	then
    V_sn="########"
  	fi

	echo "$V_server $V_conso $V_ip_dir $V_ubic $V_sn $V_tp" | sudo tee --append /home/ibmunx/JOEL/PRUEBA/Inventario.txt   
	clear
		V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
		V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
		V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
		V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
		V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
		V_tipo=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $6}'`

		echo ""
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_TIPO  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$V_tipo  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}################################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1



	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	echo -e "${V_yelow}2${NC}) Volver al menu principal."
	read aux

	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	F_inventario;
	done

	while [[  $aux == "2" ]]
	do
	menu;
	done
	
	
fi


}

########################################
# Funcion baja del inventario.         #
########################################
F_delete_s(){
clear
V_servidor="Servidor"
V_consola="Consola"
V_ip_prod="IP_Prod"
V_ubicacion="Ubicacion"
V_serial_id="Num_serie"
V_TIPO="Tipo"
echo "Ingrese servidor:"
read V_server

V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
V_tipo=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $6}'`
V_os="Sist_ope"
V_re="Release"
V_status="Status"
STATUS="Online"
ssh_test;
ping_test;
test_os;
clear

if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			
			echo -e "${V_yellow}1${NC}) Volver al menu principal."
			read aux

		while [ $aux -lt 1 ] || [ $aux -gt 1 ] || [ $aux == ""]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
				if [ $aux -eq 1 ] ; then
				menu
				fi
fi


if [[  $PING_TEST == "ERROR" ]];
	then
	echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
	echo -e "${V_yellow}1${NC}) Continuar con la baja del servidor ${V_red}$V_server${NC} en el inventario"
	echo -e "${V_yellow}2${NC}) Volver al menu principal"
	read aux

	clear

		while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "valor incorrecto ingrese la opción correcta"
			read aux
		done
		
		if [[  $aux == "1" ]]
		then

			STATUS="Offline"
			OS="##########"
			RELEASE="##########"
		else 
		menu;
		fi
	
	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}######################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}######################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

	echo ""
	echo "Se va a eliminar el siguiente registro del inventario correspondiente al servidor $V_serv."
	echo "¿Esta seguro que desea borrarlo?"
	echo -e "${V_yelow}y${NC}/${V_yelow}n${NC}"
	read aux

	END=0

	while [ "$END" -eq "0" ]
	do
  		if [ "$aux" == "y" -o "${aux}" == "n" ]
   		then
    	END=1
   		else
    	echo -e "Ingresaste un valor incorrecto, contestar con ${V_yelow}y${NC}/${V_yelow}n${NC}:"
   		read aux
		fi
	done

	if [[  $aux == "y" ]]
	then
	sudo sed -i "/${V_serv}/d" /home/ibmunx/JOEL/PRUEBA/Inventario.txt

	echo -e "${V_cyan}Se elimino el registro correspondiente al servidor ${V_red}$V_server${NC} del inventario.${NC}"


	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	echo -e "${V_yelow}2${NC}) Volver al menu principal."
	read aux

	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	F_inventario;
	done

	while [[  $aux == "2" ]]
	do
	menu;
	done
	fi
	if [[  $aux == "n" ]]
	then
	echo -e "${V_cyan}No se elimino ningun registro del inventario.${NC}"
	echo ""
	echo ""
	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	echo -e "${V_yelow}2${NC}) Volver al menu principal."
	read aux
	
	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	F_inventario;
	done

	while [[  $aux == "2" ]]
	do
	menu;
	done
	fi	

fi

if [[ $SSH_TEST == "ERROR" ]];
then


		OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
		RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
	
	if [[  $OS == "Linux" ]];
	then
		RELEASE=`sudo /home/ibmunx/JOEL/PRUEBA/trunc_release_linux.sh $V_server|tr -d "\015"`
	fi

fi

	sudo touch /home/ibmunx/JOEL/temp.txt
	echo "$V_servidor  |$V_consola  |$V_ip_prod  |$V_ubicacion  |$V_serial_id  |$V_os  |$V_re  |$V_status" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	echo "$V_serv  |$V_con  |$V_ip  |$V_ubi  |$V_serial  |$OS  |$RELEASE  |$STATUS" | sudo tee --append /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1
	clear
	echo -e "${V_cyan}######################################################################################################################################${NC}"
	echo "`sudo cat /home/ibmunx/JOEL/temp.txt`"|column -t -s "|"
	echo -e "${V_cyan}######################################################################################################################################${NC}"
	sudo rm -f /home/ibmunx/JOEL/temp.txt > /dev/null 2>&1

	echo ""
	echo "Se va a eliminar el siguiente registro del inventario correspondiente al servidor $V_serv."
	echo "¿Esta seguro que desea borrarlo?"
	echo -e "${V_yelow}y${NC}/${V_yelow}n${NC}"
	read aux

	END=0

	while [ "$END" -eq "0" ]
	do
  		if [ "$aux" == "y" -o "${aux}" == "n" ]
   		then
    	END=1
   		else
    	echo -e "Ingresaste un valor incorrecto, contestar con ${V_yelow}y${NC}/${V_yelow}n${NC}:"
   		read aux
		fi
	done

if [[  $aux == "y" ]]
then
	sudo sed -i "/${V_serv}/d" /home/ibmunx/JOEL/PRUEBA/Inventario.txt

	echo -e "${V_cyan}Se elimino el registro correspondiente al servidor ${V_red}$V_server${NC} del inventario.${NC}"


	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	echo -e "${V_yelow}2${NC}) Volver al menu principal."
	read aux

	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	F_inventario;
	done

	while [[  $aux == "2" ]]
	do
	menu;
	done
fi
if [[  $aux == "n" ]]
	then
	echo -e "${V_cyan}No se elimino ningun registro del inventario.${NC}"
	echo ""
	echo ""
	echo -e "${V_yelow}1${NC}) Volver al menu anterior."
	echo -e "${V_yelow}2${NC}) Volver al menu principal."
	read aux
	
	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
	echo "Valor incorrecto ingrese la opción correcta:"
	read aux
	done

	while [[  $aux == "1" ]]
	do
	F_inventario;
	done

	while [[  $aux == "2" ]]
	do
	menu;
	done
fi


}


########################################
#Funcion auditoria Oracle              #
########################################
F_ora_audit_report(){
clear

echo "Ingrese servidor en el cual se va a correr el Reporte de auditoria de Oracle"
read V_server
ssh_test;
ping_test;
clear
if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi

	if [[  $SSH_TEST == "ERROR" ]];
		then
		echo -e "${V_red}PROGRESO DE LA EJECUCION DEL SCRIPT DE AUDITORIA:${NC}:"
		PROCESS=collect_audit_oracleRE.sh
		${SSH} ibmunx@apsatellitep03  "sudo  /home/ibmunx/JOEL/barra.sh $V_server $PROCESS"
		clear
		echo ""
		echo -e "Se dejo el reporte en el serivdor  ${V_cyan}dbcrinf01${NC} en el directorio ${V_cyan}/archives/Oracle/TGT${NC}:"
		echo ""
		
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

	fi

		test_os;

		sudo nohup /home/ibmunx/JOEL/PRUEBA/collect_audit_oracleRE.sh $V_server </dev/null &>/dev/null & 
		clear
		 echo -e "${V_red}PROGRESO DE LA EJECUCION DEL SCRIPT DE AUDITORIA:${NC}:"
		PROCESS=collect_audit_oracleRE.sh
		F_barra_de_carga;
			echo ""
			echo -e "Se dejo el reporte en el serivdor  ${V_cyan}dbcrinf01${NC} en el directorio ${V_cyan}/archives/Oracle/TGT${NC}:"
			echo ""
			echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

}

########################################
#Funcion Barra de carga                #
########################################
F_barra_de_carga(){
END=0
porcentaje=0
while [ $END -eq 0 ]
do
if [[ `ps -ef | grep -v grep | grep $PROCESS` == "" ]];
   then
    porcentaje=100
    echo -ne '[ ################################################## (100%) ]\r'
    END=1
  

 else
    porcentaje=${porcentaje}+1
	if [[ "$porcentaje" -lt 10 ]]; then
 		echo -ne '[ # (1%) ]\r'    
       		porcentaje=$((porcentaje+1))
 		sleep 1
    	elif [[ "$porcentaje" -gt 10 && "${porcentaje}" -lt 20 ]]; then
  		echo -ne '[ ### (20%) ]\r'    
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 20 && "${porcentaje}" -lt 30 ]]; then
  		echo -ne '[ ###### (30%) ]\r'
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 30 && "${porcentaje}" -lt 40 ]]; then
  		echo -ne '[ ########## (40% ]\r'
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 40 && "${porcentaje}" -lt 50 ]]; then
  		echo -ne '[ ################ (50%) ]\r'    
 		porcentaje=$((porcentaje+1)) 
		sleep 1
    	elif [[ "$porcentaje" -gt 50 && "${porcentaje}" -lt 60 ]]; then
  		echo -ne '[ ######################## (60%) ]\r' 
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 60 && "${porcentaje}" -lt 70 ]]; then
  		echo -ne '[ ################################## (70%) ]\r' 
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 70 && "${porcentaje}" -lt 80 ]]; then
  		echo -ne '[ ######################################## (80%) ]\r'
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	elif [[ "$porcentaje" -gt 80 && "${porcentaje}" -lt 90 ]]; then
  		echo -ne '[ ########################################### (90%) ]\r'
		porcentaje=$((porcentaje+1)) 
 		sleep 1
    	else [[ "$porcentaje" -gt 90 && "${porcentaje}" -lt 99 ]];
  		echo -ne '[ ################################################ (99%) ]\r'    
 		sleep 1
		porcentaje=$((porcentaje+1)) 

fi
fi


done
}

########################################
#Funcion Generacion de casos           #
########################################
F_gen_caso(){
clear
echo "Ingrese servidor en por el cual va abrir un caso en roer:"
read V_server
V_serv=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` 
V_con=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $2}'`
V_ip=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $3}'` 
V_ubi=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $4}'`
V_serial=`cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $5}'`
V_os="Sist_ope"
V_re="Release"
V_status="Status"
ssh_test;
ping_test;
clear



if [[  $PING_TEST == "ERROR" ]];
then
		echo -e "${V_cyan}INFO: El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping.${NC}"
		echo -e "${V_yellow}1${NC}) Continuar con la generacion del caso para el servidor ${V_red}$V_server${NC}."
		echo -e "${V_yellow}2${NC}) Volver al menu principal"
		read aux


	clear

	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done


	while [[  $aux == "1" ]]
	do
			STATUS="Offline"
			if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
   			then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			echo -e "¿Desea agregar al servidor ${V_red}$V_server${NC} al inventario?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux
				if [ $aux -eq 1 ] ; then
				F_add_s;	
				else
				menu

				fi
			fi
	done



	while [[  $aux == "2" ]]
	do
		menu;
	done
	
fi


if [[  $SSH_TEST == "ERROR" ]];
then

		if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
   			then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			echo -e "¿Desea agregar al servidor ${V_red}$V_server${NC} al inventario?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux
				if [ $aux -eq 1 ] ; then
				F_add_s;	
				else
				menu

				fi
		fi

OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}' `
RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}' `

	echo "Ingrese la problematica del caso:"
	read PROBLEM
		if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt | grep -wi $V_server | awk '{print $4}' | grep -i vel` == "" ]];
		then
		V_dir="Luis Viale 1957, C.A.B.A."
		else
		V_dir="Cruz del Sud 2943, C.A.B.A."
		fi

echo "Se va a enviar el siguiente mail:"
echo ""
echo -e "${V_cyan}Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com${NC}" 

echo ""
			echo "Desea enviar el mail?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux
while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		if [[  $aux == "1" ]]
		then
#		echo -e "Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com " |mail -s "From:TLF-UNX@kyndryl.comTLF-UNX@kyndryl.com Generacion de caso de severidad 1" support-latam@evernex.com

 echo -e "Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com " | mail -s "$(echo -e "Generacion de caso de harware\nFrom: UNIX TGT <TLF-UNX@kyndryl.com> Reply-to: TLF-UNX@kyndryl.com\nContent-Type: text/html\n")" Matias.Joel.Giannini@kyndryl.com


		echo ""
		echo "Se evio el mail a Roer"
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

		clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done	
		else
		menu
		fi




fi

if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt  | grep -wi $V_server | awk '{print $1}'` == "" ]]
   			then
			echo -e "El servidor ${V_red}$V_server${NC} no se encuentra en el inventario."
			echo -e "¿Desea agregar al servidor ${V_red}$V_server${NC} al inventario?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux
				if [ $aux -eq 1 ] ; then
				F_add_s;	
				else
				menu

				fi
fi

	echo "Ingrese la problematica del caso:"
	read PROBLEM
		if [[ `cat /home/ibmunx/JOEL/PRUEBA/Inventario.txt | grep -wi $V_server | awk '{print $4}' | grep -i vel` == "" ]];
		then
		V_dir="Luis Viale 1957, C.A.B.A."
		else
		V_dir="Cruz del Sud 2943, C.A.B.A."
		fi

echo "Se va a enviar el siguiente mail:"
echo ""
echo -e "${V_cyan}Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com${NC}" 

echo ""
			echo "Desea enviar el mail?"
			echo -e "${V_yellow}1${NC}) Si"
			echo -e "${V_yellow}2${NC}) No"
			read aux
while [ $aux -lt 1 ] || [ $aux -gt 2 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		if [[  $aux == "1" ]]
		then
#		echo -e "Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com " |mail -s "From: TLF-UNX@kyndryl.com Generacion de caso de severidad 1" support-latam@evernex.com

 echo -e "Se solicita la apertura de un caso de hardware de severidad 1. \nSe detallan los datos del equipo: \n\nProblemática: \n$PROBLEM \n\nDatos del servidor: \nHostname: $V_serv \nSerial number: $V_serial \n\nUbicacion fisica del equipo: \n$V_dir \n$V_ubi \n\nDatos de contacto: \nMail: \nTLF-UNX@kyndryl.com \nTelefono: \n+54-911-5286-1180 \n\nDesde ya muchas gracias, saludos. \n\n\nKYNDRYL UNIX TEAM \nCIC Argentina, Global Technology Services \nPHONE: +54-911-5286-1180 \nE-mail: TLF-UNX@kyndryl.com " | mail -s "$(echo -e "Generacion de caso de harware\nFrom: UNIX TGT <TLF-UNX@kyndryl.com> Reply-to: TLF-UNX@kyndryl.com\nContent-Type: text/html\n")" Matias.Joel.Giannini@kyndryl.com


		echo ""
		echo "Se evio el mail a Roer"
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

		clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done	
		else
		menu
		fi


}



######################################
# Funcion configurar multipath alies #
######################################
F_conf_multipath_alies(){
i=
clear
echo -e "${V_cyan}################################################################################${NC}"
echo -e "${V_cyan}# Configurar multipath alies.                                                  #${NC}"
echo -e "${V_cyan}################################################################################${NC}"
echo ""
echo "Ingrese servidor:"
read V_server
clear



case $V_server in
"ct3racp101") F_server_case ;;
"ct3racp102") F_server_case ;;
"ct3racp103") F_server_case ;;
"ct3racp104") F_server_case ;;
"ct3racp105") F_server_case ;;
"ct3racp106") F_server_case ;;
"ct3racp107") F_server_case ;;
"ct3racp108") F_server_case ;;
"ct3racp109") F_server_case ;;
"ct3racp110") F_server_case ;;
"ct3racp111") F_server_case ;;
"ct3racp112") F_server_case ;;
"ct3racp201") F_server_case ;;
"ct3racp202") F_server_case ;;
"ct3racp203") F_server_case ;;
"ct3racp204") F_server_case ;;
"ct3racp205") F_server_case ;;
"ct3racp206") F_server_case ;;
"ct3racp207b") F_server_case ;;
"ct3racp208") F_server_case ;;
"ct3racp209") F_server_case ;;
"ct3racp110") F_server_case ;;
"ct3racp111") F_server_case ;;
"ct3racp112") F_server_case ;;
esac

	

echo -e "${V_cyan}################################################################################${NC}"
echo -e "${V_cyan}Esta funcion solo es valida para los siguientes servidores:                     ${NC}"
echo -e  "${V_red}ct3racp101 ct3racp102 ct3racp103 ct3racp104 ct3racp105 ct3racp106 ct3racp107    ${NC}" 
echo -e  "${V_red}ct3racp108 ct3racp111 ct3racp112 ct3racp201 ct3racp202 ct3racp203 ct3racp203    ${NC}" 
echo -e  "${V_red}ct3racp204 ct3racp205 ct3racp206 ct3racp207b ct3racp208 ct3racp209 ct3racp210   ${NC}"  
echo -e  "${V_red}ct3racp211 ct3racp212                                                           ${NC}"
echo -e "${V_cyan}################################################################################${NC}"
echo ""			
echo -e "${V_yellow}1${NC}) Volver al menu principal:"
read aux

				
					while [ $aux -lt 1 ] || [ $aux -gt 1 ]
					do
					echo "valor incorrecto ingrese la opción correcta"
					read aux
					done

					while [[  $aux == "1" ]]
					do
					menu;
					done				



}

######################################
# Funcion lectura de alias           #
######################################
F_lec_multipath_alies(){
clear
		V_bkp=`${SSH} ibmunx@$V_server "sudo ls /etc/multipath.conf.bkp-${dia}-${mes}-${anio}"|tr -d "\015"`
		if [[ $V_bkp == "/etc/multipath.conf.bkp-${dia}-${mes}-${anio}" ]]; then
		echo -e "${V_cyan}Ya hay un Bkp del archivo multipath.conf del dia de hoy.${NC}"
		echo -e "${V_cyan}Puede seguir con la tarea a realizar de forma segura.${NC}"
		echo""
		else
		${SSH} ibmunx@$V_server "sudo cp /etc/multipath.conf /etc/multipath.conf.bkp-${dia}-${mes}-${anio}"
		echo -e "${V_cyan}Se realizo una copia de seguridad del archivo.${NC}"
		echo -e "${V_cyan}Puede seguir con la tarea a realizar de forma segura.${NC}"
		echo""
		fi
echo "Ingrese alias:" 
read v_alias
while [[ $v_alias == `${SSH} ibmunx@$V_server "sudo cat /etc/multipath.conf" | grep -wi $v_alias | awk '{print $2}'|tr -d "\015"` ]]
do
echo -e "${V_cyan}#############################################################################################${NC}"
echo -e "El alias ingresado ya se encuentra en el archivo /etc/multipath.conf del servidor $V_server"
echo -e "${V_cyan}#############################################################################################${NC}"
echo ""
echo "Por favor ingrese otro."
echo "Ingrese alias:"
read v_alias
done
}


######################################
# Funcion lectura de lun_id          #
######################################
F_lec_multipath_lun_id(){
echo -e "${V_red}-----------------------------------------------------------------------------------------------${NC}"
echo -e "${V_red}|IMPORTANTE: Storage manda los luns_id sin el 3 adelante y todos los caracteres en mayuscula. |${NC}"
echo -e "${V_red}|Pegarlas tal cual las pasa storage que este script le agrega el 3 faltande y las             |${NC}" 
echo -e "${V_red}|pasa a minuscula.                                                                            |${NC}"
echo -e "${V_red}|Ejemplo:                                                                                     |${NC}" 
echo -e "${V_red}|Como los manda storage 60002AC0000000000600466B0001DCA4.                                     |${NC}"
echo -e "${V_red}|Como deberian ir en el archivo 360002ac0000000000600466b0001dca4.                            |${NC}" 
echo -e "${V_red}|Tambien se puede poner el lunid con el 3 incluido. En este caso independientemente de que el |${NC}" 
echo -e "${V_red}|lun ID este en mayuscula o minuscula se pasa a minuscula                                     |${NC}" 
echo -e "${V_red}-----------------------------------------------------------------------------------------------${NC}"
echo""
echo "ingrese lun_id" 
read v_lun_id
clear
if  [[ `echo $v_lun_id| cut -b1` != "3" ]]
then
v_lun_id=`echo "3$v_lun_id" | tr '[:upper:]' '[:lower:]'` 
echo "Se mofico el valor ingresado a $v_lun_id"
else
v_lun_id=`echo "$v_lun_id" | tr '[:upper:]' '[:lower:]'` 
echo "$v_lun_id"
fi

while [[ $v_lun_id == `${SSH} ibmunx@$V_server "sudo cat /etc/multipath.conf" | grep -wi $v_lun_id | awk '{print $2}'|tr -d "\015"` ]]
do
clear
echo -e "${V_cyan}#############################################################################################${NC}"
echo -e "El lun_id ingresado ya se encuentra en el archivo /etm/multipath.conf del servidor $V_server"
echo -e "${V_cyan}#############################################################################################${NC}"
echo""
echo "Por favor ingrese otro."
echo "ingrese lun_id" 
read v_lun_id
if  [[ `echo $v_lun_id| cut -b1` != "3" ]]
then
v_lun_id=`echo "3$v_lun_id" | tr '[:upper:]' '[:lower:]'` 
else
v_lun_id=`echo "$v_lun_id" | tr '[:upper:]' '[:lower:]'` 
fi

done
}


######################################
# Funcion agregar de lun_id          #
######################################
F_add_multipath_lun_id(){
${SSH} ibmunx@$V_server "sudo sed -i '/multipaths {/a multipath { \n 	alias  ${v_alias}\n	wwid   ${v_lun_id}\n}' /etc/multipath.conf"
}


######################################
# Fuuncion F_server_case             #
######################################
F_server_case(){
ping_test;
ssh_test;
clear
if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi

	if [[  $SSH_TEST == "ERROR" ]];
	then
		OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
		RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
				if [[ "$OS" == "Linux" ]];
 				then
				END=0
				while [[  $END == "0" ]];
				do
					echo "Ingrese alias:" 
					read v_alias
					
echo -e "${V_red}-----------------------------------------------------------------------------------------------${NC}"
echo -e "${V_red}|IMPORTANTE: Storage manda los luns_id sin el 3 adelante y todos los caracteres en mayuscula. |${NC}"
echo -e "${V_red}|Pegarlas tal cual las pasa storage que este script le agrega el 3 faltande y las             |${NC}" 
echo -e "${V_red}|pasa a minuscula.                                                                            |${NC}"
echo -e "${V_red}|Ejemplo:                                                                                     |${NC}" 
echo -e "${V_red}|Como los manda storage 60002AC0000000000600466B0001DCA4.                                     |${NC}"
echo -e "${V_red}|Como deberian ir en el archivo 360002ac0000000000600466b0001dca4.                            |${NC}" 
echo -e "${V_red}|Tambien se puede poner el lunid con el 3 incluido. En este caso independientemente de que el |${NC}" 
echo -e "${V_red}|lun ID este en mayuscula o minuscula se pasa a minuscula                                     |${NC}" 
echo -e "${V_red}-----------------------------------------------------------------------------------------------${NC}"

					echo "ingrese lun_id" 
					read v_lun_id
		
  					$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/multipath_alies_conf.sh $V_server $v_alias $v_lun_id"
		
					echo""
					echo -e "${V_yellow}1${NC}) Agregar otro lun_id con alias"
					echo -e "${V_yellow}2${NC}) Escanear luns y hacer un reload al servicio del multipath"
					echo -e "${V_yellow}3${NC}) Volver al menu principal"
					read aux
					clear
					while [ $aux -lt 1 ] || [ $aux -gt 3 ]
					do
						echo "Valor incorrecto ingrese la opción correcta:"
						read aux
					done
					if  [[ $aux == "1" ]]; then
						END=0
					elif [[ $aux == "2" ]]; then
  					$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/scan.sh $V_server"  					$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/multi_reload.sh $V_server"					echo ""
					echo -e "${V_yellow}1${NC}) Volver al menu principal"
					read aux
					while [ $aux -lt 1 ] || [ $aux -gt 1 ]
					do
						echo "Valor incorrecto ingrese la opción correcta:"
						read aux
					done
					menu;			
					else
						END=1
						menu
						
					fi
					done
   		else
    	    	echo "Esta funcion solo es valida para servidores Red Hat:"
				echo ""
				echo -e "${V_yellow}1${NC}) Volver al menu principal"
				read aux
				clear
	
				while [ $aux -lt 1 ] || [ $aux -gt 1 ]
				do
					echo "Valor incorrecto ingrese la opción correcta:"
					read aux
				done
			
				while [[  $aux == "1" ]]
				do
					menu
				done
   		fi
	fi


	test_os;
	if [ "$OS" != "Linux" ]
	then 
	    	    echo "Esta funcion solo es valida para servidores Red Hat:"
				echo ""
				echo -e "${V_yellow}1${NC}) Volver al menu principal"
				read aux
				clear
	
				while [ $aux -lt 1 ] || [ $aux -gt 1 ]
				do
					echo "Valor incorrecto ingrese la opción correcta:"
					read aux
				done
			
				while [[  $aux == "1" ]]
				do
					menu
				done
	fi

	echo -e "${V_yellow}1${NC}) Agregar lun_id con alias al Archivo /etc/multipath.conf"
	echo -e "${V_yellow}2${NC}) Volver al menu principal"
	read aux

	while [ $aux -lt 1 ] || [ $aux -gt 2 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	echo "$aux"

	while [[  $aux == "1" ]] || [[  $aux == "2" ]]
	do
		if [ $aux -eq 1 ] ; then
		

		F_lec_multipath_alies
		F_lec_multipath_lun_id
		F_add_multipath_lun_id


		else
		menu

		fi
	echo""
	echo -e "${V_yellow}1${NC}) Agregar otro lun_id con diferente alias"
	echo -e "${V_yellow}2${NC}) Escanear luns y hacer un reload al servicio del multipath"
	echo -e "${V_yellow}3${NC}) Volver al menu principal"
	read aux
			while [ $aux -lt 1 ] || [ $aux -gt 3 ]
			do
				echo "Valor incorrecto ingrese la opción correcta:"
				read aux
			done
			if [[ "$aux" == "2" ]]; then
					F_scan;
					F_multi_reload;
					echo -e "${V_yellow}1${NC}) Volver al menu principal"
					read aux
					while [ $aux -lt 1 ] || [ $aux -gt 1 ]
					do
						echo "Valor incorrecto ingrese la opción correcta:"
						read aux
					done
					menu;
			elif [[ "$aux" == "3" ]]; then
			menu;
			fi
	done
}

######################################
# Fuuncion SOX.                      #
######################################
F_sox(){
clear

echo "Ingrese servidor en el cual se va a aplicar SOX"
read V_server
ssh_test;
ping_test;
clear
if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi

	if [[  $SSH_TEST == "ERROR" ]];
		then
		OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}'|tr -d "\015"`
		RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}'|tr -d "\015"`
		$SSH ibmunx@apsatellitep03 "sudo nohup sh /home/ibmunx/JOEL/PRUEBA/soxRE.sh $V_server $OS </dev/null &>/dev/null &" 
		echo -e "${V_red}PROGRESO DE LA EJECUCION DEL SCRIPT DE SOX:${NC}:"
		PROCESS="soxRE.sh"
		${SSH} ibmunx@apsatellitep03  "sudo  /home/ibmunx/JOEL/barra.sh $V_server $PROCESS"
		clear
		echo ""
		echo -e "Se aplico SOX en el servidor ${V_cyan}$V_server${NC}"
		echo ""
		
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

	fi

		test_os;


		sudo nohup sh /home/ibmunx/JOEL/PRUEBA/soxRE.sh $V_server $OS </dev/null &>/dev/null & 
		clear
		 echo -e "${V_red}PROGRESO DE LA EJECUCION DEL SCRIPT DE SOX:${NC}:"
		PROCESS="soxRE.sh"
		F_barra_de_carga;
			echo ""
			echo -e "Se termino la Ejecucion de SOX en el servidor $V_server:"
			echo ""
			echo -e "${V_yellow}1${NC}) Volver al menu principal:"
			read aux

			clear
	
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
		done
		while [[  $aux == "1" ]]
		do
			menu
		done

		

}

######################################
# Fuuncion escaneo de discos         #
######################################
F_scan(){
$SSH ibmunx@$V_server "for i in `ls /sys/class/scsi_host/ |tr -d '\015'`; do echo '- - -' | sudo tee /sys/class/scsi_host/$i/scan > /dev/null 2>&1; done"
}
######################################
# Fuuncion multipath reload          #
######################################
F_multi_reload(){
$SSH ibmunx@$V_server "sudo /sbin/service multipathd reload"
}
######################################
# Fuuncion  SSH test                 #
######################################
ssh_test(){
SSH_TEST=`$SSH ibmunx@$V_server "uname >/dev/null" >/dev/null 2>&1&& echo "OK" ||echo "ERROR"`
}
######################################
# Fuuncion ping test                 #
######################################
ping_test(){
PING_TEST=`ping -c1 $V_server >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
}
######################################
# Fuuncion OS test                   #
######################################
test_os() {
SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes -o ConnectTimeout=5"
OS=`$SSH ibmunx@$V_server "uname 2>/dev/null"|tr -d "\015"`

if [[ "$OS" == "Linux" ]]
then
#Valida Red hat OS
	if [[ `$SSH ibmunx@$V_server "cat /etc/redhat-release 2>/dev/null"|tr -d "\015"` != "" ]]
	then
		RELEASE=`$SSH ibmunx@$V_server "cat /etc/redhat-release 2>/dev/null"|tr -d "\015"| tr ' ' '_'| sed  "s/_Enterprise_Linux_Server_release_/_/g"`
	fi 
#Valida SUSE OS
	if [[ `$SSH ibmunx@$V_server "cat /etc/os-release 2>/dev/null" | grep PRETTY_NAME` != "" ]]
	then
		RELEASE=`$SSH ibmunx@$V_server "cat /etc/os-release | grep PRETTY_NAME" | awk -F'"' '{print $2}' |tr -d "\015"| tr ' ' '_'`
	fi 
#Valida oracle linux OS
	if [[ `$SSH ibmunx@$V_server "cat /etc/oracle-release 2>/dev/null" |awk '{print $1}' |tr -d "\015"` == "Oracle" ]]
	then
	RELEASE=`$SSH ibmunx@$V_server "cat /etc/oracle-release 2>/dev/null" |tr -d "\015"| tr ' ' '_'`
	fi
#Valida Ubuntu
	if [[ `$SSH ibmunx@$V_server "cat /etc/lsb-release 2>/dev/null" | grep  -i Description` != "" ]]
	then
	RELEASE=`$SSH ibmunx@$V_server "cat /etc/lsb-release" | grep  -i Description 2>/dev/null | awk -F'"' '{print $2}' |tr -d "\015"| tr ' ' '_'`
	fi
fi 

if [ "$OS" == "AIX" ]
then
	RELEASE=`$SSH ibmunx@$V_server "oslevel -s 2>/dev/null"|tr -d "\015"`
fi
if [ "$OS" == "SunOS" ]
then
	RELEASE=`$SSH ibmunx@$V_server "uname -r 2>/dev/null"|tr -d "\015"`
fi
}

F_fs_aix(){
$SSH ibmunx@$V_server "sudo cat /etc/filesystems" > /tmp/filesystem_temp
cat /tmp/filesystem_temp |grep -vw "log"| grep -B 1 "/dev/" | grep -vw "dev"| grep  "/" |grep -v "cdrom" | grep -v "/mkcd/" |sed -e 's/://g'|tr -d "\015"
for i in `cat /tmp/filesystem_temp |grep -vw "log"| grep -B 1 "/dev/" | grep -vw "dev"| grep  "/" |grep -v "cdrom" | grep -v "/mkcd/" |sed -e 's/://g'|tr -d "\015"`; do 
i=`echo "$i"|tr -d "\015"`
if [[ `$SSH ibmunx@$V_server "df -k | grep -w $i"` == "" ]]
then
	$SSH ibmunx@$V_server "sudo mount -a > /dev/null 2>&1"
		aux=`$SSH ibmunx@$V_server "df -k" | grep -w "$i" | awk '{print $7}'|tr -d "\015"`
		if [[ $aux == "" ]] 
		then
			echo "Se intento montar el FS $i pero el mismo no monta. Por favor verificar en el servidor."
			echo ""
			$SSH ibmunx@$V_server "df -k" | grep -w "$i" 
			echo ""
		else
			echo "Se monto el fs $aux" 
		fi
else

echo "El Filesistem $i se encuentra montado"
fi
done
sudo rm -f /tmp/filesystem_temp > /dev/null 2>&1
}

F_install_elastic(){
clear
echo "Ingrese servidor en el cual se va a installar elasticserch"
read V_server
clear
			

			echo -e "${V_cyan}Elija la version que se va a instalar:${NC}"
			echo -e "${V_yellow}1${NC}) ${V_yellow}elasticsearch-7.16.2${NC}"
			echo -e "${V_yellow}2${NC}) Volver al menu principal:"
			read aux

			while [ $aux -lt 1 ] || [ $aux -gt 2 ]
			do
			echo "Valor incorrecto ingrese la opción correcta:"
			read aux
			done

			if [[  $aux == "1" ]]; then
			F_install_elastic_ver;
			else
			menu;
			fi 

}

F_install_elastic_ver(){
ping_test;
ssh_test;
if [[  $PING_TEST == "ERROR" ]];
then
	echo -e "${V_cyan}El servidor${NC} ${V_red}$V_server${NC}${V_cyan} no responde ping, favor de verificar si el servidor es correcto o si el mismo tiene algun inconveniente.${NC}"
	echo -e "${V_yellow}1${NC}) Volver al menu principal"
	read aux

	clear

	while [ $aux -lt 1 ] || [ $aux -gt 1 ]
	do
		echo "valor incorrecto ingrese la opción correcta"
		read aux
	done

	while [[  $aux == "1" ]]
	do
		menu;
	done
	
fi

if [[  $SSH_TEST == "ERROR" ]];
then
		OS=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $1}' `
		RELEASE=`$SSH ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/test_os.sh $V_server"|awk '{print $2}' `
		
		if [ "$OS" == "AIX" ]
 		then
		echo -e "Esta funcion no esta habilitado para servidores AIX"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi

		if [ "$OS" == "SunOS" ]
 		then
		echo -e "Esta funcion no esta habilitado para servidores Solaris"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi


		if [ "$OS" == "Linux" ]
 		then
		echo -e "Es Linux"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi

fi

test_os;
		if [ "$OS" == "AIX" ]
 		then
		echo -e "Esta funcion no esta habilitado para servidores AIX"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi

		if [ "$OS" == "SunOS" ]
 		then
		echo -e "Esta funcion no esta habilitado para servidores Solaris"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi


		if [ "$OS" == "Linux" ]
 		then
		$SCP /home/ibmunx/JOEL/PRUEBA/elasticsearch-7.16.2-x86_64.rpm  ibmunx@$V_server:/home/ibmunx/
		#$SSH ibmunx@$V_server "sudo systemctl stop elasticsearch"
		sleep 1
		$SSH ibmunx@$V_server "sudo cp -r /etc/elasticsearch/ /etc/elasticsearch-bkp-${dia}-${mes}-${anio}"
		$SSH ibmunx@$V_server "sudo cp /etc/sysconfig/elasticsearch /home/ibmunx"
		rmver=`$SSH ibmunx@$V_server "sudo rpm -qa"| grep  '^elasticsearch'|tr -d "\015"`
		#$SSH ibmunx@$V_server "sudo rpm -e $rmver"
		#$SSH ibmunx@$V_server "sudo rpm --install /home/ibmunx/elasticsearch-7.16.2-x86_64.rpm"
		#$SSH ibmunx@$V_server "sudo cp /etc/elasticsearch-bkp-${dia}-${mes}-${anio}/elasticsearch.yml /etc/elasticsearch"
		#$SSH ibmunx@$V_server "sudo cp /home/ibmunx/elasticsearch /etc/sysconfig"
		#$SSH ibmunx@$V_server "sudo systemctl enable elasticsearch.service"
		#$SSH ibmunx@$V_server "sudo systemctl daemon-reload"
		#$SSH ibmunx@$V_server "sudo systemctl start elasticsearch.service"
		#$SSH ibmunx@$V_server "sudo systemctl status elasticsearch.service"
		echo -e "${V_cyan}____________________________ $V_server _______________________________${NC}"
		$SSH ibmunx@$V_server "/usr/sbin/ifconfig -a"
		echo -e "${V_cyan}______________________________________________________________________${NC}"
		echo ""
		echo "Ingrese ip para realizar la prueba del servicio"
		read ipcurl
		clear
		echo -e "${V_cyan}______________________________ CURL __________________________________${NC}"
		$SSH ibmunx@$V_server "curl http://$ipcurl:9200/"
		echo -e "${V_cyan}______________________________________________________________________${NC}"
		echo ""
		echo -e "${V_yellow}1${NC}) Volver al menu principal:"
		read aux
		while [ $aux -lt 1 ] || [ $aux -gt 1 ]
		do
		echo "Valor incorrecto ingrese la opción correcta:"
		read aux
		done
		while [[  $aux == "1" ]]
		do
		menu
		done

		fi


}


menu;

