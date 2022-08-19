#!/bin/ksh
###############################################
#
#  Remediacion_AIX5.sh
#
#  Plantilla de seguridad para AIX 5 de los archivos de configuración 
#  Adicionalmente, deben ejecutarse a mano los puntos no automatidos.
#
#
###############################################

imprimir()
{
mje=$1
   echo "\n" $mje
}

validar_file()
{
cual=$1
printf "Validando $cual modelo.......  "
if [ -f $cual ]
then
         printf "[  OK  ]\n\n"
        
else
        printf "[FAILED]\n\n"
        exit 99
fi
}

validar_backup_previo()
{
echo
echo "----------------------------------------------------------------"
echo
echo "Ejecutó el backup previo (./backup_preSOX.sh)? y/n    default:n"
read  answer
case $answer in
        yes|Yes|y)
                echo Backup previo OK! Iniciando script remediador!
                ;;
        *)
                echo Ejecute script de backup previo!!
                exit 90
                ;;
esac
}


#  validar_aix()
#  {
#  AIXVERSION=$(oslevel)
#  if [ $AIXVERSION = "5.3.0.0" ]
#  then
#          echo OSLEVEL Version $AIXVERSION
#          printf "Iniciando script de remediacion SOX para AIX 5.3...\n\n"
#  else
#          echo OSLEVEL Version $AIXVERSION
#          printf "ERROR: Este script sólo aplica a AIX 5.3 \n\n"
        #  exit 90
#  fi
#  }

validar_aix()
{
AIXVERSION=$(oslevel)
OS=`echo $AIXVERSION|cut -d"." -f1|awk '{print $1}'`
case $AIXVERSION in
  6.1.0.0|5.3.0.0|7.1.0.0)
                
                echo OSLEVEL Version $AIXVERSION
                printf "Iniciando script de remediacion SOX para AIX 5.3, AIX 6.1 o AIX 7.1...\n\n"
                ;;
 
                *)                 
                echo OSLEVEL Version $AIXVERSION
                printf "ERROR: Este script sólo aplica a AIX 5.3, AIX 6.1 o AIX 7.1...\n\n"
                exit
esac
}

audit_config() {
printf "start: \n" 
printf "\t binmode = on \n" 
printf "\t streammode = off \n" 
printf "bin: \n" 
printf "\t trail = /audit/trail \n" 
printf "\t bin1 = /audit/bin1 \n" 
printf "\t bin2 = /audit/bin2 \n" 
printf "\t binsize = 10240 \n" 
printf "\t cmds = /etc/security/audit/bincmds \n" 
printf " \n" 
printf "stream: \n" 
printf "\t streamcompact = off \n" 
printf "\t cmds = /etc/security/audit/streamcmds \n" 
printf " \n" 
printf "classes: \n" 
printf "\t general = USER_SU,PASSWORD_Change,FILE_Unlink,FILE_Link,FILE_Rename,FS_Chdir,FS_Chroot,PORT_Locked,PORT_Change,FS_Mkdir,FS_Rmdir \n" 
printf "\t objects = S_ENVIRON_WRITE,S_GROUP_WRITE,S_LIMITS_WRITE,S_LOGIN_WRITE,S_PASSWD_READ,S_PASSWD_WRITE,S_USER_WRITE,AUD_CONFIG_WR \n" 
printf "\t SRC = SRC_Start,SRC_Stop,SRC_Addssys,SRC_Chssys,SRC_Delssys,SRC_Addserver,SRC_Chserver,SRC_Delserver \n" 
printf "\t kernel = PROC_Create,PROC_Delete,PROC_Execute,PROC_RealUID,PROC_AuditID,PROC_RealGID,PROC_Environ,PROC_Limits,PROC_SetPri,PROC_Setpri,PROC_Privilege,PROC_Settimer \n" 
printf "\t files = FILE_Open,FILE_Read,FILE_Write,FILE_Close,FILE_Link,FILE_Unlink,FILE_Rename,FILE_Owner,FILE_Mode,FILE_Acl,FILE_Privilege,DEV_Create,File_copy \n" 
printf "\t svipc = MSG_Create,MSG_Read,MSG_Write,MSG_Delete,MSG_Owner,MSG_Mode,SEM_Create,SEM_Op,SEM_Delete,SEM_Owner,SEM_Mode,SHM_Create,SHM_Open,SHM_Close,SHM_Owner,SHM_Mode \n" 
printf "\t mail = SENDMAIL_Config,SENDMAIL_ToFile \n" 
printf "\t cron = AT_JobAdd,AT_JobRemove,CRON_JobAdd,CRON_JobRemove,CRON_Start,CRON_Finish \n" 
printf "\t tcpip = TCPIP_config,TCPIP_host_id,TCPIP_route,TCPIP_connect,TCPIP_data_out,TCPIP_data_in,TCPIP_access,TCPIP_set_time,TCPIP_kconfig,TCPIP_kroute,TCPIP_kconnect,TCPIP_kdata_out,TCPIP_kdata_in,TCPIP_kcreate \n" 
printf "\t ipsec = IPSEC_chtun,IPSEC_export,IPSEC_gentun,IPSEC_imptun,IPSEC_lstun,IPSEC_mktun,IPSEC_rmtun,IPSEC_chfilt,IPSEC_expfilt,IPSEC_genfilt,IPSEC_trcbuf,IPSEC_impfilt,IPSEC_lsfilt,IPSEC_mkfilt,IPSEC_mvfilt,IPSEC_rmfilt,IPSEC_unload,IPSEC_stat,IKE_tnl_creat,IKE_tnl_delet,IPSEC_p1_nego,IPSEC_p2_nego,IKE_activat_cmd,IKE_remove_cmd \n" 
printf "\t lvm = LVM_AddLV,LVM_KDeleteLV,LVM_ExtendLV,LVM_ReduceLV,LVM_KChangeLV,LVM_AvoidLV,LVM_MissingPV,LVM_AddPV,LVM_AddMissPV,LVM_DeletePV,LVM_RemovePV,LVM_AddVGSA,LVM_DeleteVGSA,LVM_SetupVG,LVM_DefineVG,LVM_KDeleteVG,LVM_ChgQuorum,LVM_Chg1016,LVM_UnlockDisk,LVM_LockDisk,LVM_ChangeLV,LVM_ChangeVG,LVM_CreateLV,LVM_CreateVG,LVM_DeleteVG,LVM_DeleteLV,LVM_VaryoffVG,LVM_VaryonVG \n" 
printf "\t ldapserver = LDAP_Bind,LDAP_Unbind,LDAP_Add,LDAP_Delete,LDAP_Modify,LDAP_Modifydn,LDAP_Search,LDAP_Compare \n" 
printf "\t aacct=AACCT_On,AACCT_Off,AACCT_AddFile,AACCT_ResetFile,AACCT_RmFile,AACCT_SwtchFile,AACCT_TridOn,AACCT_TridOff,AACCT_SysIntOff,AACCT_SysIntSet,AACCT_PrIntOff,AACCT_PrIntSet,AACCT_SwtchProj,AACCT_AddProj,AACCT_RmProj,AACCT_PolLoad,AACCT_PolUnload,AACCT_NotChange,AACCT_NotifyOff \n" 
printf "\t wparmgtclass = WM_CreateWPAR,WM_RemoveWPAR,WM_StartWPAR,WM_StopWPAR,WM_RebootWPAR,WM_SyncWPAR,WM_CheckptWPAR,WM_ResumeWPAR,WM_RestartWPAR,WM_ModifyWPAR,WM_SetInitConf,WM_SetMonIntv,WM_SetTierMnDsc,WM_ResetConfig,WM_ModifyConfig \n" 
printf " \n" 
printf "users: \n" 
printf "\t root = general,SRC,cron,tcpip \n" 
printf "\t default = general,SRC,cron,tcpip \n"
printf " \n" 
printf "role: \n" 
}

syslog_file() {
printf "# IBM_PROLOG_BEGIN_TAG \n"
printf "# This is an automatically generated prolog. \n"
printf "# \n"
printf "# bos610 src/bos/etc/syslog/syslog.conf 1.11 \n"
printf "# \n"
printf "# Licensed Materials - Property of IBM \n"
printf "# \n"
printf "# COPYRIGHT International Business Machines Corp. 1988,1989 \n"
printf "# All Rights Reserved \n"
printf "# \n"
printf "# US Government Users Restricted Rights - Use, duplication or \n"
printf "# disclosure restricted by GSA ADP Schedule Contract with IBM Corp. \n"
printf "# \n"
printf "# @(#)34        1.11  src/bos/etc/syslog/syslog.conf, cmdnet, bos610 4/27/04 14:47:53 \n"
printf "# IBM_PROLOG_END_TAG \n"
printf "# \n"
printf "# COMPONENT_NAME: (CMDNET) Network commands. \n"
printf "# \n"
printf "# FUNCTIONS: \n"
printf "# \n"
printf "# ORIGINS: 27 \n"
printf "# \n"
printf "# (C) COPYRIGHT International Business Machines Corp. 1988, 1989 \n"
printf "# All Rights Reserved \n"
printf "# Licensed Materials - Property of IBM \n"
printf "# \n"
printf "# US Government Users Restricted Rights - Use, duplication or \n"
printf "# disclosure restricted by GSA ADP Schedule Contract with IBM Corp. \n"
printf "# \n"
printf "# /etc/syslog.conf - control output of syslogd \n"
printf "# \n"
printf "# \n"
printf "# Each line must consist of two parts:- \n"
printf "# \n"
printf "# 1) A selector to determine the message priorities to which the \n"
printf "#    line applies \n"
printf "# 2) An action. \n"
printf "# \n"
printf "# Each line can contain an optional part:- \n"
printf "# \n"
printf "# 3) Rotation. \n"
printf "# \n"
printf "# The fields must be separated by one or more tabs or spaces. \n"
printf "# \n"
printf "# format: \n"
printf "# \n"
printf "# <msg_src_list> <destination> [rotate [size <size> k|m] [files <files>] [time <time> h|d|w|m|y] [compress] [archive <archive>]] \n"
printf "# \n"
printf "# where <msg_src_list> is a semicolon separated list of <facility>.<priority> \n"
printf "# where: \n"
printf "# \n"
printf "# <facility> is: \n"
printf "#       * - all (except mark) \n"
printf "#       mark - time marks \n"
printf "#       kern,user,mail,daemon, auth,... (see syslogd(AIX Commands Reference)) \n"
printf "# \n"
printf "# <priority> is one of (from high to low): \n"
printf "#       emerg/panic,alert,crit,err(or),warn(ing),notice,info,debug \n"
printf "#       (meaning all messages of this priority or higher) \n"
printf "# \n"
printf "# <destination> is: \n"
printf "#       /filename - log to this file \n"
printf "#       username[,username2...] - write to user(s) \n"
printf "#       @hostname - send to syslogd on this machine \n"
printf "#       * - send to all logged in users \n"
printf "# \n"
printf "# [rotate [size <size> k|m] [files <files>] [time <time> h|d|w|m|y] [compress] [archive <archive>]] is: \n"
printf "#       If <destination> is a regular file and the word "rotate" is \n"
printf "#       specified, then the <destination> is limited by either \n"
printf "#       <size> or <time>, or both <size> and <time>. The <size> causes \n"
printf "#       the <destination> to be limited to <size>, with <files> files \n"
printf "#       kept in the rotation. The <time> causes the <destination> to be rotated after \n"
printf "#       <time>. If both <time> and <size> are specified then logfiles \n"
printf "#       will be rotated once the the logfile size exceeds the <size> \n"
printf "#       or after <time>, whichever is earlier. The rotated filenames \n"
printf "#       are created by appending a period and a number to <destination>, \n"
printf "#       starting with ".0". \n"
printf "# \n"
printf "#       If compress option is specified then the logfile names will be \n"
printf "#       generated with a ".Z" extension. The files keyword will be applicable \n"
printf "#       to the logfiles which are currently under rotation. For example \n"
printf "#       if we specify the compress option then only fileis with ".Z" extension \n"
printf "#       will be under rotation and number of such files will be limited by \n"
printf "#       <files> files. Any logfiles with an extension other than ".Z" \n"
printf "#       will not be under the rotation scheme and thus will not be within \n"
printf "#       the limit of <files> files. Similarly if we remove the compress \n"
printf "#       option then the files which have been generated with ".Z" extension \n"
printf "#       will no longer be the part of rotation scheme and will not be limited \n"
printf "#       by the <files> files. \n"
printf "# \n"
printf "#       The minimum size that can be specified is 10k, the minimum \n"
printf "#       number of files that can be specified is 2. The default \n"
printf "#       size is 1m (meg) and the default for <files> is unlimited. \n"
printf "#       Therefore, if only "rotate" is specified, the log will be \n"
printf "#       rotated with <size> = 1m. \n"
printf "#       The compress option means that rotated log files that are not \n"
printf "#       in use will be compressed. \n"
printf "#       The archive option will save rotated log files that are not \n"
printf "#       in use to <archive>. \n"
printf "#       The default is not to rotate log files. \n"
printf "#       Note: It is recommended not to use same destination file in \n"
printf "#       multiple entries when using file rotation. \n"
printf "# \n"
printf "# example: \n"
printf "# "mail messages, at debug or higher, go to Log file. File must exist." \n"
printf "# "all facilities, at debug and higher, go to console" \n"
printf "# "all facilities, at crit or higher, go to all users" \n"
printf "#  mail.debug           /usr/spool/mqueue/syslog \n"
printf "#  *.debug              /dev/console \n"
printf "#  *.crit                       * \n"
printf "#  *.debug              /var/log/syslog.debug100k.out  rotate size 100k files 4 \n"
printf "#  *.crit               /var/log/syslog.dailycrit.out  rotate time 1d \n"
printf "# ASO log configuration \n"
printf "# aso.notice /var/log/aso/aso.log rotate size 1m files 8 compress \n"
printf "# aso.info /var/log/aso/aso_process.log rotate size 1m files 8 compress \n"
printf "# aso.debug /var/log/aso/aso_debug.log rotate size 32m files 8 compress \n"
printf " \n"
printf "auth.info               /var/adm/authlog \n"
printf "auth.debug              /var/adm/authlog \n"
printf "*.info;auth.none        /var/adm/syslog         rotate size 1024k files 4 compress \n"
printf "*.warn;auth.none        /var/adm/messages       rotate size 1024k files 4 compress \n"
printf " \n"
printf " \n"
printf "*.* @10.167.19.51 \n"
printf "*.info;auth.none;*.warn;auth.debug @10.167.19.51 \n"
printf " \n"
}

common_variables() {
if [ "$OS" == "7" ]
 then
  SSH_PARAM="Protocol 2|LogLevel INFO|X11Forwarding no|MaxAuthTries 4|IgnoreRhosts yes|HostbasedAuthentication no|PermitRootLogin yes|PermitEmptyPasswords no|PermitUserEnvironment no|ClientAliveInterval 300|UsePrivilegeSeparation  yes|ClientAliveCountMax 0|Banner /etc/motd|MACs hmac-sha1,umac-64@openssh.com,hmac-ripemd160|X11Forwarding no"
  # RhostsAuthentication lo saque porque hubo problemas en svaix040
 else
  SSH_PARAM="Protocol 2|LogLevel INFO|X11Forwarding no|IgnoreRhosts yes|HostbasedAuthentication no|PermitRootLogin yes|PermitEmptyPasswords no|PermitUserEnvironment no|ClientAliveInterval 300|ClientAliveCountMax 0|Banner /etc/motd|X11Forwarding no"
### Cipher en 5 y 6 da error levantando sshd lo saque tambien MaxAuthTries 4 no levanta 
fi
  SSH_EXCL="ClientAliveInterval 7200"
  AUDIT_OBJECTS="/etc/group|/etc/passwd|/etc/security/group|/etc/security/passwd|/etc/opasswd|/etc/security/audit/config|/etc/security/audit/objects|/etc/security/audit/events|/etc/sudoers|/etc/security/login.defs|/etc/security/limits|/etc/ssh/sshd_config|/etc/syslog.conf|/var/adm/cron/cron.allow|/var/adm/cron/cron.deny|/var/adm/cron/at.allow|/var/adm/cron/at.deny|/etc/cron.hourly/|/etc/cron.daily/|/etc/cron.weekly/|/etc/cron.monthly/|/etc/cron.d/|/etc/crontab"
  FILEAUDIT=/etc/security/audit/objects
  FILE_PROFILE=/etc/profile
}

verif_sshd_version() {
echo "Verifica donde estan los archivos de configuracion"
DIR_INSTALL=`lslpp -f openssh*|grep "\/etc\/"|tail -1|tr -d " "|cut -d"/" -f1,2`
if [ "$DIR_INSTALL" == "/etc" ]
 then
   FILE_SSH="/etc/ssh/sshd_config"
   cp /etc/ssh/sshd_config /etc/ssh/sshd_config.prev.sox
 else
   FILE_SSH="/usr/local/etc/sshd_config"
   cp /usr/local/etc/sshd_config /etc/ssh/sshd_config.prev.sox
fi
}

verif_ssh(){
#Verifica punto 7.5.3
echo "################## Modifica punto 7.5.3"
echo "$SSH_PARAM"| tr "|" "\n"|while read SSH_LINE
 do
  SSH_VALUE=`grep "^$SSH_LINE" $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$SSH_LINE $SSH_VALUE"
done
}

exep_ssh(){
#suprime variables seteadas a pedido del cliente
echo "$SSH_EXCL"|tr "|" "\n"|while read SSH_NM
 do
  SSH_PARAM_EX=`echo $SSH_NM|awk '{print $1}'`
  SSH_VALUE_EX=`echo $SSH_NM|awk '{print $2}'`
  if [ "$SSH_VARIABLE" == "$SSH_PARAM_EX" ]
  then
    SSH_VALUE_CK=`grep "^${SSH_PARAM_EX}" $FILE_SSH|grep "$SSH_VALUE_EX" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
  else
    SSH_VALUE_CK="NO"
  fi
done 
}

impl_ssh(){
#Modifica punto 7.5.3
echo "################## Modifica punto 7.5.3"
echo "$SSH_PARAM"| tr "|" "\n"|while read SSH_LINE
 do
  SSH_VARIABLE=`echo $SSH_LINE|awk '{print $1}'`
  SSH_SET=`echo $SSH_LINE|awk '{print $2}'`
  echo "$SSH_VARIABLE  $SSH_SET"
  exep_ssh
  if [ "$SSH_VALUE_CK" != "OK" ]
  then
  awk -v varname="$SSH_VARIABLE" -v value="$SSH_SET" ' BEGIN {FS = OFS = " "} $1 == varname {$2 = value; found = 1} {print} END {if (! found) {print varname, value}} ' $FILE_SSH  >$FILE_SSH.tmp
  SSH_MOVE=`mv -f $FILE_SSH.tmp $FILE_SSH`
  SSH_VALUE=`grep "^$SSH_LINE" $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$SSH_VARIABLE $SSH_SET"
   else
    echo "$SSH_VARIABLE $SSH_VALUE_EX excluida a pedido"
  fi
done
  SSH_CHMOD=`chmod og-rwx $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$FILE_SSH CHMOD $SSH_CHMOD"
}



##################################################
## VALIDACION DE FILES COMPLEMENTARIOS 
## QUE SON NECESARIOS PARA EJECUCION DEL SCRIPT
##
## ./append.profile     -->> Appendea al /etc/profile configuración requerida por plantilla.
## ./audit.config       -->> Reemplaza el /etc/security/audit/config de acuerdo a plantilla
## ./audit.objetcs      -->> Reemplaza el /etc/security/audit/objects de acuerdo a plantilla
## ./sshd_config        -->> Reemplaza el /etc/ssh/sshd_config y /usr/local/etc/sshd_config  de acuerdo a plantilla
## ./backup_preSOX.sh   -->> Script que genera un tar (relativo ./) de backup. Para ejecutarse antes del script de remediacion
##
##################################################

validar_aix
common_variables
echo "Estoy trabajando con AIX V $OS"

#validar_file ./backup_preSOX.sh
#validar_file ./sshd_config
#validar_file ./audit.config
#validar_file ./audit.objects
#validar_file ./append.profile

echo "Archivos necesarios encontrados OK!"

########### FIN VALIDACION ARCHIVOS NECESARIOS  ############################
############################################################################

############################################################################
###########          VALIDAR BACKUP PREVIO      ############################
############################################################################

#validar_backup_previo 

############################################################################
###########       INICIO DE SCRIPT REMEDIADOR   ############################
############################################################################

echo
echo "----------------------------------------------------------------"
echo
imprimir "Iniciando script de remediacion..."

###     7.1.1.2         Configuración del banner
# Consolidado en 7.1.1.7 Permisos en sshd_config
imprimir "7.1.1.2 Permisos en sshd_config"

###     7.1.1.3         Configuración de sshd_config
# Consolidado en 7.1.1.7 Permisos en sshd_config
imprimir "7.1.1.3       Configuración de sshd_config"

###     7.1.1.7         Permisos en sshd_config
imprimir "7.1.1.7               Permisos en sshd_config"

printf "****************************************************************************************\r
*  El uso de este Sistema está restringido y será monitoreado de acuerdo               *\r
*  a lo establecido en la Política General de Seguridad de la Información (TMA-SI-001) *\r
*  Este sistema es una herramienta de trabajo provista por Telefónica para uso         *\r
*  exclusivo de usuarios autorizados.                                                  *\r
*  El uso no autorizado o indebido será pasible de sanciones. Toda persona que utilice *\r
*  este sistema autoriza expresamente a la compañía a realizar las verificaciones      *\r
*  tendientes a determinar el correcto uso en cumplimiento de la política.             *\r
****************************************************************************************\n" >/etc/motd
chown bin:bin /etc/motd
chmod 644 /etc/motd

#mkdir -p /etc/ssh
#mkdir -p /usr/local/etc

#cp -p ./sshd_config /etc/ssh/sshd_config
#cp -p ./sshd_config /usr/local/etc/sshd_config

####se modifico para que no pise configuraciones existentes
verif_sshd_version
impl_ssh
echo "############## VERIFICAR SSH A MANO #################"
verif_ssh
##########################################################

###     7.1.1.8         Permisos en sshd_config y rshd
imprimir "7.1.1.8               Permisos en sshd_config y rshd"
chown root:system /etc/ssh/sshd_config
chmod og-rw /etc/ssh/sshd_config

chown root:system /usr/local/etc/sshd_config
chmod og-rw /usr/local/etc/sshd_config

stopsrc -s sshd
startsrc -s sshd

chown root:system /usr/sbin/rshd
chmod ugo= /usr/sbin/rshd

###     "       7.1.2   SERVIDOR SNMP"
imprimir "      7.1.2   SERVIDOR SNMP"
cat /etc/snmpd.conf  |  awk '/public/ && $1 == "community"   { $1 = "#Audit_SOX "$1 }; {print}' > /tmp/snmpd.conf.SOX
cat /tmp/snmpd.conf.SOX > /etc/snmpd.conf

cat /etc/snmpd.conf  | awk '/system/ && $1 == "community"   { $1 = "#Audit_SOX "$1 }; {print}' > /tmp/snmpd.conf.SOX
cat /tmp/snmpd.conf.SOX > /etc/snmpd.conf

cat /etc/snmpd.conf  | awk '/private/ && $1 == "community"   { $1 = "#Audit_SOX "$1 }; {print}' > /tmp/snmpd.conf.SOX
cat /tmp/snmpd.conf.SOX > /etc/snmpd.conf
rm /tmp/snmpd.conf.SOX


###     7.1.3           SERVICIOS REMOTOS
imprimir "7.1.3                 SERVICIOS REMOTOS"
echo Estado Previo ...
ls -l /usr/bin/rcp 
ls -l /usr/bin/rlogin
ls -l /usr/bin/rsh

echo Modificando 7.1.3...
chmod ugo= /usr/bin/rcp
chmod ugo= /usr/bin/rlogin
chmod ugo= /usr/bin/rsh

###     7.1.4.2         Validar la configuración en el archivo /etc/security/audit/config
imprimir "7.1.4.2       Validar la configuración en el archivo /etc/security/audit/config"
echo Montaje del /audit
df -m /audit
#cp ./audit.config /etc/security/audit/config
cp /etc/security/audit/config /etc/security/audit/config.orig
audit_config >/etc/security/audit/config

###     7.1.4.3         Clases asignadas a usuarios creados
imprimir "7.1.4.3       Clases asignadas a usuarios creados"
chsec -f /usr/lib/security/mkuser.default -s user -a auditclasses="general,SRC,cron,tcpip"

###     7.1.4.5 (EXCEPTUADA)
imprimir "7.1.4.5       (EXCEPTUADA)"
lsitab audit
mkitab "audit:2:boot:audit start > /dev/console 2>&1 # Start audit"

###     7.1.4.4         Rotación de archivos mediante Cron
imprimir "7.1.4.4       Rotación de archivos mediante Cron"
EXISTECRON=$(crontab -l | grep -c /etc/security/aixpert/bin/cronaudit )
if [ $EXISTECRON -eq 0 ]
then
        printf "Agredando cronaudit"
        echo "0 * * * * /etc/security/aixpert/bin/cronaudit" >> /var/spool/cron/crontabs/root
        
else
        printf "Cronaudit ya existe en linea de cron\n"
        crontab -l | grep  /etc/security/aixpert/bin/cronaudit
fi
echo


###     7.1.4.6         Auditoría de objetos
imprimir "7.1.4.6               Auditoría de objetos"
#cp ./audit.objects /etc/security/audit/objects
mv $FILEAUDIT ${FILEAUDIT}.orig
echo "$AUDIT_OBJECTS"|tr "|" "\n"|while read X
do
AUDITO=`grep $X $FILEAUDIT >/dev/null 2>&1 && echo "$X OK" ||echo "$X NO_ESTA"`
echo $AUDITO
if [ "$AUDITO" == "$X NO_ESTA" ]
 then
   echo ENTRE
   echo "${X}:" >>$FILEAUDIT
   echo '\t w = "TAG_WRITE"' >>$FILEAUDIT
   echo '\t r = "TAG_READ"' >>$FILEAUDIT
   echo '\t x = "TAG_RUN"' >>$FILEAUDIT
   echo " " >>$FILEAUDIT
fi
done


###     7.1.5           CONFIGURACIÓN DE HISTORY EXTENDIDO
imprimir "7.1.5         CONFIGURACIÓN DE HISTORY EXTENDIDO"
mkdir -p /var/log/hist ; chmod 777 /var/log/hist
chown root:system /var/log/hist ;ls -ld /var/log/hist
EXISTEHISTORY=$(cat $FILE_PROFILE | grep -c "Capture shell history" )
if [ $EXISTEHISTORY -eq 0 ]
then
        printf "Agregando configuración de HISTORY EXTENDIDO a /etc/profile\n"
        #cat ./append.profile >> /etc/profile
        echo "# Capture shell history" >>$FILE_PROFILE
	echo "From=\`who am i | awk '{ print \$1 }'\`">>$FILE_PROFILE
	echo "To=\`/usr/bin/whoami | awk '{ print \$1 }'\`">>$FILE_PROFILE
	echo "File=\$From:\$To">>$FILE_PROFILE
	echo "if [ ! -d /var/log/hist/\$To ] ; then">>$FILE_PROFILE
	echo "    mkdir -p /var/log/hist/\$To">>$FILE_PROFILE
	echo "    chmod 700 /var/log/hist/\$To">>$FILE_PROFILE
	echo "fi">>$FILE_PROFILE
	echo "HISTFILE=/var/log/hist/\$To/.sh_history.\$File">>$FILE_PROFILE
	echo "HISTSIZE=2048">>$FILE_PROFILE
	echo "HISTTIMEFORMAT='%F %T >> '">>$FILE_PROFILE
	echo "export HISTFILE HISTSIZE HISTTIMEFORMAT">>$FILE_PROFILE
	echo "PROFILE ADD OK"
else
        printf "Conriguración de history extendido ya existe en /etc/profile\n"
        cat $FILE_PROFILE | grep -p "Capture shell history"
fi
echo

verif_syslog() {
CNTSYS=`cat /etc/syslog.conf|wc -l`
if [ "$CNTSYS" -lt "3" ]
then
  echo "####### ESTA ROTO SYSLOG.CONF"
  syslog_file >/etc/syslog.conf
fi
}

###     7.1.6.1         Configurar envío de logs a SIEM
imprimir "      7.1.6.1         Configurar envío de logs a SIEM"
cp /etc/syslog.conf /etc/syslog.conf.prev.sox
verif_syslog
cat /etc/syslog.conf | grep -v 10.167.19 > /tmp/syslog.conf.temp
echo "*.* @10.167.19.51">> /tmp/syslog.conf.temp
echo "*.info;auth.none;*.warn;auth.debug @10.167.19.51">> /tmp/syslog.conf.temp
cp -f /tmp/syslog.conf.temp /etc/syslog.conf
stopsrc -s syslogd; sleep 1;
startsrc -s syslogd

###     7.1.6.2         Prevención de recepción de mensajes
imprimir "7.1.6.2       Prevención de recepción de mensajes"
chssys -s syslogd -a "-r"
stopsrc -s syslogd; sleep 1
startsrc -s syslogd


###     7.2.2           SERVICIO DE CORREO SENDMAIL
imprimir "7.2.2         SERVICIO DE CORREO SENDMAIL"
cat /etc/mail/sendmail.cf |sed -e 's/O SmtpGreetingMessage=.*/O SmtpGreetingMessage=mailerready/g' > /tmp/sendmail.cf.SOX
cat /tmp/sendmail.cf.SOX > /etc/mail/sendmail.cf
rm /tmp/sendmail.cf.SOX


###     7.2.3           SERVIDOR Y CLIENTE DE NIS
###     7.2.3.1         Desinstalar Nis Server
imprimir "7.2.3.1               Desinstalar Nis Server"
lslpp -l bos.net.nis.server
/usr/lib/instl/sm_inst installp_cmd -u -f 'bos.net.nis.server'
###     7.2.3.2         Desinstalar Nis client
imprimir "7.2.3.2       Desinstalar Nis client"
lslpp -l bos.net.nis.client*
/usr/lib/instl/sm_inst installp_cmd -u -f 'bos.net.nis.client*'

###     7.2.5           DESHABILITAR GUI LOGIN
imprimir "7.2.5                 DESHABILITAR GUI LOGIN - EXCEPTUADA"
# EXEPTUADA
#/usr/dt/bin/dtconfig -d
#La agrego para que no reporte el script
mkdir -p /etc/dt/config/
echo "Xsun -nolisten tcp" >/etc/dt/config/Xservers
chmod 444 /etc/dt/config/Xservers
chown root:bin /etc/dt/config/Xservers


###     7.2.6 SERVICIO 
imprimir "7.2.6 SERVICIO NTP"
cat /etc/ntp.conf | grep -v "^server" >  /etc/ntp.conf
cat /etc/ntp.conf | grep -v "^restrict" >  /etc/ntp.conf
SERVERNAME=$(uname -n)
TIPO=$( echo $SERVERNAME | egrep -ci  "serve|svaix|srvrh|srvsun|int")
### SI TIPO = 1 es TASA, SI TIPO=0 es TMA
case $TIPO in
                1)
                echo Configurando NTP de TASA para $SERVERNAME
                echo "server soteclock        " >> /etc/ntp.conf
                echo "server soteclock2       "  >> /etc/ntp.conf
                echo "server soteclock3      "  >> /etc/ntp.conf
                ;;

                0)
                echo Configurando NTP de TMA para $SERVERNAME
                ## EN TMA el NTP es el default gateway
                DG=$(netstat -nr | grep default | awk {'print $2'})
                echo "server $DG        " >> /etc/ntp.conf
                ;;
esac
echo "restrict -4 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
echo "restrict -6 default kod nomodify notrap nopeer noquery" >> /etc/ntp.conf
chrctcp -a xntpd
stopsrc -s xntpd
startsrc -s xntpd
lssrc -ls xntpd

###     7.2.7           SERVICIOS DE RED PROVISTOS POR INETD
imprimir "7.2.7                 SERVICIOS DE RED PROVISTOS POR INETD"
refresh -s inetd 
lssrc -ls inetd

chsubserver -r inetd -C /etc/inetd.conf -d -v 'telnet' -p 'tcp6'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'exec' -p 'tcp6'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'daytime' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'daytime' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'shell' -p 'tcp6'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'cmsd' -p 'sunrpc_udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'ttdbserver' -p 'sunrpc_tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'uucp' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'time' -p 'udp' 
chsubserver -r inetd -C /etc/inetd.conf -d -v 'time' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'login' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'talk' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'ntalk' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'ftp' -p 'tcp6'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'chargen' -p 'tcp' 
chsubserver -r inetd -C /etc/inetd.conf -d -v 'chargen' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'discard' -p 'tcp' 
chsubserver -r inetd -C /etc/inetd.conf -d -v 'discard' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'dtspc' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'echo' -p 'tcp' 
chsubserver -r inetd -C /etc/inetd.conf -d -v 'echo' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'pcnfsd' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'rstatd' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'rusersd' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'rwalld' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'sprayd' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'klogin' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'kshell' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'rquotad' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'tftp' -p 'udp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'imap2' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'pop3' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'finger' -p 'tcp'
chsubserver -r inetd -C /etc/inetd.conf -d -v 'instsrv' -p 'tcp'

refresh -s inetd 
lssrc -ls inetd


###     7.2.8           SUBSERVICIO TCP
imprimir "7.2.8         SUBSERVICIO TCP"
chrctcp -d snmpd
chrctcp -d dhcpcd
chrctcp -d dhcpsd
chrctcp -d autoconf6
chrctcp -d gated
chrctcp -d mrouted
chrctcp -d named
chrctcp -d routed
chrctcp -d rwhod
chrctcp -d timed
chrctcp -d hostmibd
chrctcp -d dpid2
chrctcp -d snmpmibd
chrctcp -d aixmibd
chrctcp -d ndpd-host
chrctcp -d ndpd-router

###     7.2.9           SERVICIO INITTAB
imprimir "7.2.9                 SERVICIO INITTAB"
rmitab qdaemon
rmitab piobe
rmitab l4ls
rmitab httpdlite
rmitab writesrv
rmitab pmd
rmitab lpd
rmitab rcnfs 

###     7.2.10          PARÁMETROS DE KERNEL
imprimir "7.2.10                PARÁMETROS DE KERNEL"
ipsrcrouteforward=0 lo modifique recien
#no -p -o ipsrcrouteforward=1 		#
no -p -o ipignoreredirects=1
no -p -o clean_partial_conns=1
no -p -o ipsrcroutesend=0
no -p -o ipsendredirects=0
no -p -o directed_broadcast=0
no -p -o icmpaddressmask=0
no -p -o nonlocsrcroute=0
no -p -o ipsrcrouterecv=0
if [ "$OS" == "7" ]
 then
   no -p -o ip6srcrouteforward=0
   no -p -o rfc1323=1
   no -p -o sockthresh=60
   no -p -o tcp_mssdflt=1448
   no -p -o tcp_pmtu_discover=0
   no -p -o tcp_recvspace=262144
   no -p -o tcp_sendspace=262144
   no -p -o tcp_tcpsecure=7
   no -p -o udp_pmtu_discover=0
   nfso -p -o portcheck=1 
   nfso -p -o nfs_use_reserved_ports=1
fi


###     7.3.1           AJUSTE DE PERMISOS EN ARCHIVOS DE REGISTRO SOLO PARA ADMINISTRADOR
echo
echo
echo  "7.3.1            AJUSTE DE PERMISOS EN ARCHIVOS DE REGISTRO SOLO PARA ADMINISTRADOR"
###     7.3.1.1         /etc/security
imprimir "7.3.1.1               /etc/security"
ls -ld /etc/security | awk '{print $1 " " $3 " " $4 " " $9}'
chown -R root:security /etc/security
chmod u=rwx,g=rx,o= /etc/security
chmod -R go-w,o-rx /etc/security

###     7.3.1.2         /etc/group
imprimir "7.3.1.2       /etc/group"
ls -l /etc/group | awk '{print $1 " " $3 " " $4 " " $9}'
chown root:security /etc/group
chmod u=rw,go=r /etc/group

###     7.3.1.3         /etc/passwd
imprimir "7.3.1.2       /etc/group"
ls -l /etc/passwd | awk '{print $1 " " $3 " " $4 " " $9}'
chown root:security /etc/passwd
chmod u=rw,go=r /etc/passwd

###     7.3.1.4         Configuración de Sticky Bit
imprimir "7.3.1.4       EXCEPTUADA - Configuración de Sticky Bit"
# for part in `mount | grep dev | awk '{print $2}' | grep -Ev 'cdrom|nfs'`; do 
# echo "Searching $part" 
# find $part -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 
# done


###     7.3.1.5         /etc/security/audit
imprimir "7.3.1.5       /etc/security/audit"
ls -ld /etc/security/audit | awk '{print $1 " " $3 " " $4 " " $9}'
chown -R root:audit /etc/security/audit
chmod u=rwx,g=rx,o= /etc/security/audit
chmod -R u=rw,g=r,o= /etc/security/audit/*

###     7.3.1.6         /audit
imprimir "7.3.1.6       /audit"
ls -ld /audit | awk '{print $1 " " $3 " " $4 " " $9}'
chown root:audit /audit
chmod u=rwx,g=rx,o= /audit
chmod -R u=rw,g=r,o= /audit/*


###     7.3.1.7         /var/adm/cron/at.allow
imprimir "7.3.1.7       /var/adm/cron/at.allow"
ls -l /var/adm/cron/at.allow | awk '{print $1 " " $3 " " $4 " " $9}'
echo "root" > /var/adm/cron/at.allow
chown root:sys /var/adm/cron/at.allow
chmod u=r,go= /var/adm/cron/at.allow
chmod 660 /var/adm/cron/log

###     7.3.1.7 bis     /smit.log
imprimir "7.3.17 bis    /smit.log"
ls -l /smit.log| awk '{print $1 " " $3 " " $4 " " $9}'
chown root:sys /smit.log
chmod o-rw /smit.log


###     7.3.1.9         /etc/motd
imprimir "7.3.1.9       /etc/motd"
ls -l /etc/motd | awk '{print $1 " " $3 " " $4 " " $9}'
chown bin:bin /etc/motd
chmod u=rw,go=r /etc/motd

###     7.3.1.10        /var/adm/ras
imprimir "7.3.1.10      /var/adm/ras"
ls -ld /var/adm/ras | awk '{print $1 " " $3 " " $4 " " $9}'
ls -l /var/adm/ras | awk '{print $1 " " $3 " " $4 " " $9}'
chmod o-rw /var/adm/ras/*

###     7.3.1.11        /var/ct/RMstart.log
imprimir "7.3.1.10      /var/adm/ras"
ls -l /var/ct/RMstart.log| awk '{print $1 " " $3 " " $4 " " $9}'
chmod o-rw /var/ct/RMstart.log


###     7.3.1.12        /var/tmp/dpid2.log
imprimir "7.3.1.12      /var/tmp/dpid2.log"
ls -l /var/tmp/dpid2.log| awk '{print $1 " " $3 " " $4 " " $9}'
# Se crea file para que no falle dando file not found.
touch /var/tmp/dpid2.log
chmod o-rw /var/tmp/dpid2.log


###     7.3.1.13        /var/tmp/hostmibd.log
imprimir "7.3.1.13      /var/tmp/hostmibd.log"
ls -l /var/tmp/hostmibd.log| awk '{print $1 " " $3 " " $4 " " $9}'
# Se crea file para que no falle dando file not found.
touch /var/tmp/hostmibd.log
chmod o-rw /var/tmp/hostmibd.log

###     7.3.1.14        /var/tmp/snmpd.log
imprimir "7.3.1.14      /var/tmp/snmpd.log"
ls -l /var/tmp/snmpd.log| awk '{print $1 " " $3 " " $4 " " $9}'
# Se crea file para que no falle dando file not found.
touch /var/tmp/snmpd.log 
chmod o-rw /var/tmp/snmpd.log

###     7.3.1.15        /var/adm/sa
imprimir "7.3.1.15      /var/adm/sa"
ls -ld /var/adm/sa | awk '{print $1 " " $3 " " $4 " " $9}'
chown adm:adm /var/adm/sa
chmod u=rwx,go=rx /var/adm/sa

###     7.4.1           ARCHIVO /ETC/HOSTS.EQUIV
imprimir "7.4.1         ARCHIVO /etc/hosts.equiv"
sed '/^\s*$/d; s/^\(\s*[^#].*\)/#\1/' /etc/hosts.equiv > /etc/hosts.equiv.work 
mv hosts.equiv.work hosts.equiv 
chown root:system /etc/hosts.equiv 
chmod 644 /etc/hosts.equiv

###     7.4.4           REMOVER ARCHIVOS VACIOS DE CRONTAB
imprimir "7.4.4         REMOVER ARCHIVOS VACIOS DE CRONTAB"
chgrp -R cron /var/spool/cron/crontabs
chmod -R o= /var/spool/cron/crontabs
chown root /var/spool/cron/crontabs
chmod 770 /var/spool/cron/crontabs

###     7.4.5           Control at y cron deny/allow
imprimir "7.4.5         Control at y cron deny/allow"
echo "Configuracion de cron.allow exceptuada!..."
# echo "root" > /var/adm/cron/cron.allow
for USR in `ls /var/spool/cron/crontabs|cut -d"." -f1|sort|uniq`
 do
  echo "$USR"
done > /var/adm/cron/cron.allow
echo "root" > /var/adm/cron/at.allow
rm /var/adm/cron/at.deny
rm /var/adm/cron/cron.deny
chmod 400 /var/adm/cron/cron.allow
chown root:sys /var/adm/cron/cron.allow


###     7.5.1           POLÍTICA DE PASSWORD
imprimir "7.5.1         POLÍTICA DE PASSWORD"
chsec -f /etc/security/user -s default -a mindiff=2
chsec -f /etc/security/user -s default -a minage=2
chsec -f /etc/security/user -s default -a maxage=6
chsec -f /etc/security/user -s default -a minlen=8
chsec -f /etc/security/user -s default -a minalpha=2
chsec -f /etc/security/user -s default -a minother=2
chsec -f /etc/security/user -s default -a maxrepeats=2
chsec -f /etc/security/user -s default -a histexpire=13
chsec -f /etc/security/user -s default -a histsize=13
chsec -f /etc/security/user -s default -a maxexpired=4
if [ "$OS" == "7" ]
 then
   chsec -f /etc/security/user -s default -a mindigit=1
   chsec -f /etc/security/user -s default -a minloweralpha=1
   chsec -f /etc/security/user -s default -a minspecialchar=1
   chsec -f /etc/security/user -s default -a minupperalpha=1
   chsec -f /etc/security/user -s default -a loginretries=3
   chsec -f /etc/security/login.cfg -s usw -a logintimeout=30
   chsec -f /etc/security/login.cfg -s default -a logintimeout=30
   chsec -f /etc/security/user -s default -a histsize=20
   chsec -f /etc/security/login.cfg -s usw -a pwd_algorithm=ssha256
fi

###     7.5.2           BLOQUEO DE USUARIOS DE SISTEMA
imprimir "7.5.2         BLOQUEO DE USUARIOS DE SISTEMA"
for X in daemon bin sys adm nobody uucp lpd
do
  chuser login=false rlogin=false $X
  grep $X /etc/passwd >/dev/null && echo "$X Existe y fue modificado OK"|| echo "USUARIO $X no EXISTE"
done
#chuser login=false rlogin=false daemon
#chuser login=false rlogin=false bin
#chuser login=false rlogin=false sys
#chuser login=false rlogin=false adm
#chuser login=false rlogin=false nobody
#chuser login=false rlogin=false uucp
#chuser login=false rlogin=false lpd

###     7.5.3           MODIFICACIÓN DE LA STANZA LOGIN DE USUARIOS POR DEFAULT
imprimir "7.5.3         MODIFICACIÓN DE LA STANZA LOGIN DE USUARIOS POR DEFAULT"
chsec -f /etc/security/login.cfg -s default -a logininterval=60
chsec -f /etc/security/login.cfg -s default -a logininterval=4
chsec -f /etc/security/login.cfg -s default -a loginreenable=30
chsec -f /etc/security/login.cfg -s default -a logindelay=5
chsec -f /etc/security/login.cfg -s default -a logindisable=4
if [ "$OS" == "7" ]
then
  chsec -f /etc/security/user -s default -a loginretries=3
  chsec -f /etc/security/login.cfg -s usw -a logintimeout=30
fi

###     7.5.4           MODIFICACIÓN DE LA STANZA DEL USUARIO ROOT
imprimir "7.5.4         MODIFICACIÓN DE LA STANZA DEL USUARIO ROOT"
chsec -f /etc/security/user -s root -a rlogin=false
chsec -f /etc/security/user -s root -a sugroups="system"
chsec -f /etc/security/user -s root -a umask=077
chsec -f /etc/security/user -s root -a maxage=0
chsec -f /etc/security/user -s root -a su=true

###     7.6             Configuración del entorno de trabajo del usuario root
imprimir "7.6           Configuración del entorno de trabajo del usuario root"
mkdir /root
chmod 700 /root
touch /root/.profile
chmod 700 /root/.profile

###     7.7             Creación y configuración del usuario de seguridad de la información
imprimir "7.7           Creación y configuración del usuario de seguridad de la información"
mkgroup segcon
mkgroup segabm
useradd  -g security seginfo

###     7.8             Verificar la presencia de archivos .rhosts y/o .netrc de usuario
imprimir "7.8           EXCEPTUADA - Verificar la presencia de archivos .rhosts y/o .netrc de usuario"
# find / -name ".netrc" -exec rm {} \; 
# find / -name ".rhosts" -exec rm {} \;
rm /.netrc
rm /.rhosts

#####  VERIFICA QUE EXISTA FILESYSTEM /AUDIT
imprimir "7.XXX VERIFICA QUE EXISTA FILESYSTEM /AUDIT"
AUDIT_EXT=`df -m /audit|grep -v Filesystem|awk '{print $7}'`
if [ "$AUDIT_EXT" == "/audit" ]
 then
  imprimir "....................FILESYSTEM /AUDIT OK"
 else
  ROOTVG_FREE=`lsvg rootvg|grep "FREE PPs:"|awk '{print $7}'|tr -d "("`
  imprimir "................... /AUDIT NO ES UN FILESYSTEM... ERROR"
  if [ "$ROOTVG_FREE" -gt "2048" ]
   then
     imprimir "................... ROOTVG TIENE $ROOTVG_FREE MB PARA CREAR EL FILESYSTEM /AUDIT"
   else
    imprimir "................... ROOTVG  NO TIENE ESPACIO DISPONIBLE PARA CREAR /AUDIT.... ERROR"
   fi
fi

############### VERIFICA Y/O AGREGA LA KPUB DE SEGURIDAD ################
spkey_common() {
KPUB="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtSiP8SYFqPQ7KNHuK460LHJ3KnyofUJP3fWE4dYKWYVEGL//rS50ZyLoSvTEWVTZNVvg9kVXeiV0GHvPBnDlijB8zXZPuLBa49Rg+7SYC835vU7kLFjqoaHG+J3yAEzkHrD7rwQDxlDT2bIL1FV3uBN7fdCaACCZrFR/o3yXYr5qxE9BpJnGykdyPrB/NOsSLMMgCnFvvX/fF/H1rLAo/p7lZNJ9dOT2N8lXvcXHaPuei8m29fVHPKM3C3lo2U9jL9i89c24j19UjpdZc+0UXja+81W9Sk/bqbBVKgCuVnVbKLZX7Ye+nCrndia6KAVWv2Yx0CuTPGteh7xUWE6Raw== cconfsoc@Gstp"
SUSER="cconfsoc"
FILE_AUTH=".ssh/authorized_keys"
SUSER_HOME=`grep ${SUSER} /etc/passwd|cut -d":" -f6`
}

verif_spkey() {
spkey_common
KEY_EXT=`grep "${KPUB}" "${SUSER_HOME}/${FILE_AUTH}" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
if [ "$KEY_EXT" == "OK" ]
 then
   echo "${SUSER} PUBKEY OK"
 else
   echo "${SUSER} PUBKEY ERROR"
fi
}

impl_spkey() {
spkey_common
verif_spkey
if [ "$KEY_EXT" == "OK" ]
 then
   echo "${SUSER} PUBKEY OK"
 else
   echo "${KPUB}" >>"${SUSER_HOME}/${FILE_AUTH}"
   chmod 644 "${SUSER_HOME}/${FILE_AUTH}"
   chown cconfsoc:cconfsoc "${SUSER_HOME}/${FILE_AUTH}"
fi
}


impl_spkey
prompt_profile() {
printf "if [ \"$USER\" == root ] \n"
printf " then \n"
printf "\texport PS1=\"[$USER@\`hostname\`:\${PWD} \] # \" \n"
printf "\telse \n"
printf "\texport PS1=\"[$USER@\`hostname\`:\${PWD} \] $ \" \n"
printf "fi \n"

printf "set -o vi \n"
}
echo "Cambia PROMPT en profile"
cp /etc/profile /etc/profile.orig
prompt_profile >>/etc/profile

echo
echo "----------------------------------------------------------------"
echo "                Fin de script de remediacion                    "
echo "----------------------------------------------------------------"
echo
echo "ATENCION: No olvidar ejecutar los puntos manuales de acuerdo a plantilla:"
echo "  7.1.4.1 Sistema de archivos /audit (crear fs) de al menos 100MB. Preferentemente FUERA del rootvg"
echo
echo " Por ultimo, REINICIAR SERVER"
echo "----------------------------------------------------------------"










