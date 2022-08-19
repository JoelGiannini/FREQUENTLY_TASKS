#!/bin/bash
i=$1
AUX=`ssh -q $i "rpm -qa | grep ssaducli"`  
echo $i

if [[ $AUX == "" ]] ; then
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm no se encuentra instalado"
sudo scp -q /home/ibmunx/JOEL/ADU_REPORT/ssaducli-4.17-6.0.x86_64.rpm $i:$HOME
echo "Se copio el rpm ssaducli-4.17-6.0.x86_64.rpm en el $HOME"
echo "Se va a instalar el paquete ssaducli-4.17-6.0.x86_64.rpm"
ssh -q $i "rpm -ivh $HOME/ssaducli-4.17-6.0.x86_64.rpm" 
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm ya se encuentra instalado"
echo "Se procede a sacar el reporte"
ssh -q $i "ssaducli -f $i-adu-report.zip"
sudo scp -q $i:$HOME/$i-adu-report.zip /home/ibmunx/JOEL/ADU_REPORT/REPORTES
echo "Se realizo el reporte y se envió a /home/ibmunx/JOEL/ADU_REPORT/REPORTES"
else
echo "El paquete ssaducli-4.17-6.0.x86_64.rpm ya se encuentra instalado"
echo "Se procede a sacar el reporte"
ssh -q $i "ssaducli -f $i-adu-report.zip"
sudo scp -q $i:$HOME/$i-adu-report.zip /home/ibmunx/JOEL/ADU_REPORT/REPORTES
echo "Se realizo el reporte y se envió a /home/ibmunx/JOEL/ADU_REPORT/REPORTES"

fi
