#!/bin/sh
. ./helper_functions.sh

structure=$1
db_file=$2


if [ -f "$db_file" ]; then
 max_row_id=`cat  $db_file | wc -l`
else
 $ECHO "no csv file" 
 exit 1
fi

if [ "$CT_ROWID" = "" ] || [ "$CT_ROWID" = "EOF" ] ; then
  CT_ROWID=0
fi

ct_next_rowid=`expr $CT_ROWID + 1`
ct_first_line_cm=`cat $db_file | head -${ct_next_rowid} | tail -1 | cut -d',' -f1`
if [ "$ct_first_line_cm" = "CONNECTION_METHOD" ]; then
	ct_next_rowid=`expr $ct_next_rowid + 1`
fi

#structure=`echo $structure | tr '[:upper:]' '[:lower:]`


if [ $structure = "db" ]; then

if [ $ct_next_rowid -gt $max_row_id ]; then
   CT_ROWID="EOF"
   CT_CONNECTION_METHOD=""
   CT_ORACLE_HOME_SERVER=""
   CT_ORACLE_SID=""
   CT_OS_USER=""
   CT_TNS_NAME=""
   CT_TNS_HOST=""
   CT_TNS_PORT=""
   CT_TNS_SERVICE_NAME=""
   CT_TNS_SID=""
   CT_DB_USER=""
   CT_SQL=""
   CT_PROMPT_TEXT=""
else
 line=`cat $db_file | head -${ct_next_rowid} | tail -1`
 
 CT_ROWID=$ct_next_rowid
 CT_CONNECTION_METHOD=`echo $line | cut -d',' -f1`
 CT_ORACLE_HOME_SERVER=`echo $line | cut -d',' -f2`
 CT_ORACLE_SID=`echo $line | cut -d',' -f3`
 CT_OS_USER=`echo $line | cut -d',' -f4`
 CT_TNS_NAME=`echo $line | cut -d',' -f5`
 CT_TNS_HOST=`echo $line | cut -d',' -f6`
 CT_TNS_PORT=`echo $line | cut -d',' -f7`
 CT_TNS_SERVICE_NAME=`echo $line | cut -d',' -f8`
 CT_TNS_SID=`echo $line | cut -d',' -f9`
 CT_DB_USER=`echo $line | cut -d',' -f10`
 CT_SQL=`echo $line | cut -d',' -f11`
 CT_PROMPT_TEXT=`echo $line | cut -d',' -f12`
 
  export CT_ROWID
  export CT_CONNECTION_METHOD
  export CT_ORACLE_HOME_SERVER
  export CT_ORACLE_SID
  export CT_OS_USER
  export CT_TNS_NAME
  export CT_TNS_HOST
  export CT_TNS_PORT
  export CT_TNS_SERVICE_NAME
  export CT_TNS_SID
  export CT_DB_USER
  export CT_SQL
  export CT_PROMPT_TEXT
 
fi
 
fi
