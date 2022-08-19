for i in apt3erpp01; do
echo "Server $i"
comando=`ping -c 3 $i 2> /dev/null`
nofunciona=$?
if [ $nofunciona -eq 0 ] ; then
SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes "
SCP="sudo /usr/bin/scp -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no"
v_date=`date`
v_log="/home/ibmunx/JOEL/AUDIT_ORACLE/ouput/Audit_ora.log"
echo $i | sudo tee $v_log
echo "$v_date" | sudo tee $v_log
echo "Eliminacion del directorio /Auditoria" | sudo tee --append $v_log
${SSH} ibmunx@$i "sudo rm -rf /Auditoria" 
echo "Directorio eliminado" | sudo tee --append $v_log
echo "Creacion del directorio eliminado" |sudo tee --append  $v_log
${SSH} ibmunx@$i "sudo mkdir /Auditoria" 
echo "Directorio creado" | sudo tee --append $v_log
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
echo "Transpaso de Oracle_Collection_Tool-19.1.tar a /Auditoria" |sudo tee --append $v_log
$SCP /home/ibmunx/JOEL/AUDIT_ORACLE/Oracle_Collection_Tool-19.1.tar ibmunx@$i:/Auditoria
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
echo "Archivo Oracle_Collection_Tool-19.1.zip copiado correctamente" |sudo tee --append $v_log
echo "Descompresion del archivo Oracle_Collection_Tool-19.1.zip en el directorio /Auditoria" | sudo tee --append $v_log
${SSH} ibmunx@$i "cd /Auditoria && sudo tar -xvf Oracle_Collection_Tool-19.1.tar" 
echo "Descomprecion terminada" | sudo tee --append $v_log
echo "Cambio de permisos al directorio /Auditoria" |sudo tee --append $v_log
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
echo "Cambio de permisos realizado" | sudo tee --append $v_log
echo "Va a empezar la ejecucion del script" | sudo tee --append $v_log
${SSH} ibmunx@$i "cd /Auditoria/Oracle_Collection_Tool/Collection/bin/ && sudo ./Collection.sh -d / -L y -p all" |sudo tee --append $v_log
echo "termino la ejecucion del script" |sudo tee --append $v_log
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
echo "Compresion del Archivo del resultado de la ejecucion de script" |sudo tee --append $v_log
${SSH} ibmunx@$i "cd /Auditoria && sudo tar -cvf $i.tar *" | sudo tee --append $v_log
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
echo "Transpaso del $i.tar a bastion" |sudo tee --append $v_log
$SCP ibmunx@$i:/Auditoria/$i.tar /home/ibmunx/JOEL/AUDIT_ORACLE/ARC_ENV
${SSH} ibmunx@$i "sudo chmod -R 777 /Auditoria/"
$SCP /home/ibmunx/JOEL/AUDIT_ORACLE/ARC_ENV/$i.tar ibmunx@apsatellitep03:/home/ibmunx/JOEL/AUDIT_ORACLE/ARC_ENV/
${SSH} ibmunx@apsatellitep03 "sudo /home/ibmunx/JOEL/AUDIT_ORACLE/envia.sh"
echo "Transpaso terminado" | tee --append $v_log
echo "Trabajo terminado en el servidor $i terminado" | tee --append $v_log
fi



done
