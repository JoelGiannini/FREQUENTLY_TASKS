#######################################
#     Desarrollador: Joel Giannini    #
#     Configurar alias en multipath   #
#     Parametros: Alias y lun_id      #
#######################################
#Declaracion de variables
h=`date "+%H" `
m=`date "+%M" `
s=`date "+%S" `
dia=`date "+%d" `
mes=`date "+%m" `
anio=`date "+%Y" ` 
##############
#Funcion menu#
##############
menu(){
while :
do
clear
#ACA VA EL MENU#

echo " __  .______   .___  ___. "
echo "|  | |   _  \  |   \/   | "
echo "|  | |  |_)  | |  \  /  | "
echo "|  | |   _  <  |  |\/|  | "
echo "|  | |  |_)  | |  |  |  | "
echo "|__| |______/  |__|  |__|	by Joel Giannini "
		
echo "--------------------------------------------------"
echo " * * * * * * * * * opciónes * * * * * * * * * * "
echo "--------------------------------------------------"
echo "[1] Configurar multipath alies"
echo "[2] Salir"
echo "--------------------------------------------------"
echo "Elegi una opción [1-2]:"
read yourch
while [ $yourch -lt 1 ] || [ $yourch -gt 2 ]
do
echo "opción erronea, ingresar numero de opción entre  [1-2]:"
read yourch
done

case $yourch in
1) F_conf_multipath_alies ;;
2) echo "Hasta la vista baby!!!" ; echo "" ; echo "" ; exit 0 ;;
esac
done
}


######################################
# Funcion configurar multipath alies #
######################################
F_conf_multipath_alies(){
clear
echo "1) Agregar lun_id con alias al Archivo /etc/multipath.conf"
echo "2) Volver al menu principal"
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

V_bkp=`sudo ls "/etc/multipath.conf.bkp-${dia}-${mes}-${anio}"`
if [[ $V_bkp == "/etc/multipath.conf.bkp-${dia}-${mes}-${anio}" ]]; then
echo "Ya hay un Bkp del dia de hoy del archivo"
else
sudo scp /etc/multipath.conf /etc/multipath.conf.bkp-${dia}-${mes}-${anio}
echo "Se realizo una copia de seguridad del archivo."
fi


F_lec_multipath_alies
F_lec_multipath_lun_id
F_add_multipath_lun_id


else
menu

fi
echo "1) Agregar otro lun_id con diferente alias"
echo "2) Volver al menu principal"
read aux
done

}

######################################
# Funcion lectura de alias           #
######################################
F_lec_multipath_alies(){
clear
echo "ingrese alias" 
read v_alias
while [[ $v_alias == `sudo cat /etc/multipath.conf | grep -i $v_alias | awk '{print $2}'` ]]
do
echo "############################################"
echo "El alias ingresado ya se encuentra en el archivo /etc/multipath.conf"
echo "Por favor ingrese otro."
echo "ingrese alias" 
read v_alias
done
}


######################################
# Funcion lectura de lun_id          #
######################################
F_lec_multipath_lun_id(){
echo "-----------------------------------------------------------------------------------------------"
echo "|IMPORTANTE: Storage manda los luns_id sin el 3 adelante y todos los caracteres en mayuscula  |"
echo "|Pegarlas tal cual las pasa storage que este script le agrega el 3 faltande y las             |" 
echo "|pasa a minuscula.                                                                             |"
echo "|Ejemplo:                                                                                     |" 
echo "|Como los manda storage 60002AC0000000000600466B0001DCA4.                                     |"
echo "|Como deberian ir en el archivo 360002ac0000000000600466b0001dca4.                            |" 
echo "-----------------------------------------------------------------------------------------------"
echo "ingrese lun_id" 
read v_lun_id
v_lun_id=`echo "3$v_lun_id" | tr '[:upper:]' '[:lower:]'`
while [[ $v_lun_id == `sudo cat /etc/multipath.conf | grep -i $v_lun_id | awk '{print $2}'` ]]
do
echo "############################################"
echo "El lun_id ingresado ya se encuentra en el archivo /etm/multipath.conf"
echo "Por favor ingrese otro."
echo "ingrese lun_id" 
read v_lun_id
done
}


######################################
# Funcion agregar de lun_id          #
######################################
F_add_multipath_lun_id(){
sudo sed -i "/multipaths/a multipath { \n 	alias  ${v_alias}\n	wwid   ${v_lun_id}\n}" /etc/multipath.conf
echo " Se agrego el lun_id al /etc/multipath.conf "
echo ""
}

menu

