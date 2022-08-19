#!/bin/bash
SSH="sudo /usr/bin/ssh -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no -tt -o BatchMode=yes"
SCP="sudo /usr/bin/scp -q -i /home/ibmunx/.ssh/private_key -o StrictHostKeyChecking=no"
i=$1
AUX=`${SSH} ibmunx@$i "rpm -qa | grep -w ssaducli"`  
echo $i

if [[ $AUX == "" ]] ; then
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm no se encuentra instalado"
$SCP /home/ibmunx/JOEL/ADU_REPORT/ssaducli-4.17-6.0.x86_64.rpm ibmunx@$i:/home/ibmunx
echo "Se copio el rpm ssaducli-4.17-6.0.x86_64.rpm en el $HOME"
echo "Se va a instalar el paquete ssaducli-4.17-6.0.x86_64.rpm"
${SSH} ibmunx@$i "sudo rpm -ivh /home/ibmunx/ssaducli-4.17-6.0.x86_64.rpm" 
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm ya se encuentra instalado"
echo "Se procede a sacar el reporte"
${SSH} ibmunx@$i "sudo /usr/sbin/ssaducli -f $i-adu-report.zip"
${SSH} ibmunx@$i "sudo chmod 777 /home/ibmunx/$i-adu-report.zip"
$SCP ibmunx@$i:/home/ibmunx/$i-adu-report.zip /home/ibmunx/JOEL/ADU_REPORT/REPORTES
echo "Se realizo el reporte y se envió a /home/ibmunx/JOEL/ADU_REPORT/REPORTES"
else
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm ya se encuentra instalado"
echo "Se procede a sacar el reporte"
${SSH} ibmunx@$i "sudo /usr/sbin/ssaducli -f $i-adu-report.zip"
${SSH} ibmunx@$i "sudo chmod 777 /home/ibmunx/$i-adu-report.zip"
$SCP ibmunx@$i:/home/ibmunx/$i-adu-report.zip /home/ibmunx/JOEL/ADU_REPORT/REPORTES
echo "Se realizo el reporte y se envió a /home/ibmunx/JOEL/ADU_REPORT/REPORTES"

fi
