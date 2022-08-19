aux=$1
PROCESS=$2
F_barra_de_carga(){
END=0
porcentaje=0
while [ $END -eq 0 ]
do
if [[ `ps -ef | grep -v grep | grep -v barra.sh |grep "$PROCESS"` == "" ]];
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
PROCESS=`ps -ef | grep -v grep | grep "$PROCESS"`
done
}

sudo nohup /home/ibmunx/JOEL/$PROCESS $aux </dev/null &>/dev/null &

F_barra_de_carga;

