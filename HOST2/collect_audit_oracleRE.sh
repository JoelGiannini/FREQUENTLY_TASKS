I=$1
for i in $I; do
echo "Server $i"
comando=`ping -c 3 $i 2> /dev/null`
nofunciona=$?
if [ $nofunciona -eq 0 ] ; then

v_date=`date`
v_log="/home/ibmunx/JOEL/AUDIT_ORACLE/ouput/Audit_ora.log"


echo "$i" >> $v_log
echo "$v_date" >> $v_log
echo "Eliminacion del directorio /Auditoria" | tee --append $v_log
ssh -q $i "rm -rf /Auditoria"
echo "Directorio eliminado" | tee --append $v_log
echo "Creacion del directorio eliminado" | tee --append  $v_log
ssh -q $i "mkdir /Auditoria"
echo "Directorio creado" | tee --append $v_log
echo "Transpaso de Oracle_Collection_Tool-19.1.zip a /Auditoria" | tee --append $v_log
sudo scp -q /home/ibmunx/JOEL/AUDIT_ORACLE/Oracle_Collection_Tool-19.1.tar $i:/Auditoria | tee --append $v_log 
echo "Archivo copiado correctamente" | tee --append $v_log
echo "Descompresion del archivo Oracle_Collection_Tool-19.1.zip en el directorio /Auditoria" | tee --append $v_log
ssh -q $i "cd /Auditoria && tar -xvf Oracle_Collection_Tool-19.1.tar" | tee --append $v_log
echo "Descomprecion terminada" | tee --append $v_log
echo "Cambio de permisos al directorio /Auditoria/Oracle_Collection_Tool" | tee --append $v_log
ssh -q $i "chmod -R 777 /Auditoria" | tee --append $v_log
echo "Cambio de permisos realizado" | tee --append $v_log
echo "Va a empezar la ejecucion del script" | tee --append $v_log
ssh -q $i "cd /Auditoria/Oracle_Collection_Tool/Collection/bin/ && ./Collection.sh -d / -L y -p all" | tee --append $v_log
echo "termino la ejecucion del script" | tee --append $v_log
echo "Compresion del Archivo del resultado de la ejecucion de script" | tee --append $v_log
ssh -q $i "chmod -R 777 /Auditoria" | tee --append $v_log
ssh -q $i "cd /Auditoria && tar -cvf $i.tar *" | tee --append $v_log
echo "Transpaso del resultado al dbcrinf01:/archives/Oracle/TGT" | tee --append $v_log 
sudo scp $i:/Auditoria/$i.tar /home/ibmunx/JOEL/AUDIT_ORACLE/ARC_ENV |tee --append $v_log 
sudo scp /home/ibmunx/JOEL/AUDIT_ORACLE/ARC_ENV/$i.tar dbcrinf01:/archives/Oracle/TGT |tee --append $v_log 
echo "archivo pasado a dbcrinf01:/archives/Oracle/TGT" | tee --append $v_log
echo "Trabajo terminado en el servidor $i terminado" | tee --append $v_log

fi



done
