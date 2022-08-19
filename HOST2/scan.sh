V_server=$1
F_scan(){
ssh -q $V_server "for i in `ls /sys/class/scsi_host/ |tr -d '\015'`; do echo '- - -' | sudo tee /sys/class/scsi_host/$i/scan > /dev/null 2>&1; done"
}
F_scan;
