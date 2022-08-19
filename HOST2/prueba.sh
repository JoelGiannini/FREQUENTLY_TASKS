V_server=$1
ssh -q $V_server "service multipathd reload"
