#!/bin/sh
. ./helper_functions.sh

structure=$1
db_file=$2

if [ -f "$db_file" ]; then
  $ECHO CONNECTION_METHOD,ORACLE_HOME_SERVER,ORACLE_SID,OS_USER,TNS_NAME,TNS_HOST,TNS_PORT,TNS_SERVICE_NAME,TNS_SID,DB_USER,SQL >$db_file
fi 

if [ "$structure" = "db" ]; then
  if [ "$CT_CONNECTION_METHOD" != "" ];then
	$ECHO $CT_CONNECTION_METHOD,$CT_ORACLE_HOME_SERVER,$CT_ORACLE_SID,$CT_OS_USER,$CT_TNS_NAME,$CT_TNS_HOST,$CT_TNS_PORT,$CT_TNS_SERVICE_NAME,$CT_TNS_SID,$CT_DB_USER,$CT_SQL,$CT_PROMPT_TEXT >>$db_file
  fi
fi

