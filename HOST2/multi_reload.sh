V_server=$1
F_multi_reload(){
ssh -q $V_server "sudo /sbin/service multipathd reload"
}
F_multi_reload;
