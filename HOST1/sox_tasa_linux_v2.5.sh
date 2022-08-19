#!/bin/bash
OPTION=$1
MODULE=$2

lnx_ver() {
WHERE=`whereis lsb_release >/dev/null 2>&1`
if [ "$WHERE" != "" ]
 then
  VER=`lsb_release -sr|cut -d. -f1`
 else
  VER=`cat /etc/redhat-release|awk '{print $7}'|cut -d"." -f1`
fi
echo "VERSION = $VER"
 if [ "$VER" -lt "7" ]
  then
   echo "Fedora 5/6"
  else
   echo "Fedora 7"
 fi
}   	

common_param() {
   #ROOT_PASS="#########"
   HOSTNAME=`hostname`
   DEFAULT_GW=`netstat -rn|grep -iE "default|^0.0.0.0"|awk '{print $2}'`
   DATE=`date +%Y%d%m%H%M`
   FILE_FS=/etc/modprobe.d/CIS.conf
   FILE_SUDO=/etc/sudoers
   FILE_PASSWD=/etc/passwd
   FS_TYPE="cramfs freevxfs jffs2 hfs hfsplus squashfs udf"
   FILE_PERMS=/tmp/sox_tasa/perms_dir.txt
   FILE_YUM=/etc/yum.conf 
   FILE_GRUB2=/boot/grub2/grub.cfg
   FILE_GRUB=/boot/grub/grub.conf
   FILE_SYSCTL=/etc/sysctl.conf
   FILE_MOTD=/etc/motd
   FILE_ISSUE=/etc/issue
   FILE_ISSUE_NET=/etc/issue.net
   FILE_INETD=/etc/xinetd.d
   FILE_NTP=/etc/ntp.conf
   FILE_NTP_SYS=/etc/sysconfig/ntpd
   FILE_NTP_SERV=/usr/lib/systemd/system/ntpd.service
   FILE_AVAHI=/etc/default/avahi-daemon
   FILE_SENDMAIL=/etc/mail/sendmail.cf
   FILE_MAIL7=/etc/postfix/main.cf
   FILE_AUDIT=/etc/audit/auditd.conf
   FILE_AUDIT_RULES=/etc/audit/audit.rules
   FILE_RSYSLOGD=/etc/rsyslog.conf
   FILE_SYSLOG="/var/log/messages /var/log/secure /var/log/maillog /var/log/spooler /var/log/boot.log /var/log/cron /var/log/syslog /var/log/sudo.log"
   FILE_PROFILE=/etc/profile
   FILE_LOGROTATE=/etc/logrotate.d/syslog
   FILE_CRON="/etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d"
   FILE_SSH=/etc/ssh/sshd_config
   FILE_PASS_AUTH=/etc/pam.d/password-auth
   FILE_SYS_AUTH=/etc/pam.d/system-auth
   FILE_SYS_AUTH_AC=/etc/pam.d/system-auth-ac
   FILE_PASS_AUTH=/etc/pam.d/password-auth
   FILE_PAM=/etc/security/pwquality.conf
   FILE_SECURE=/etc/security
   FILE_LOGINDEF=/etc/login.defs
   FILE_PWQUALITY=/etc/security/pwquality.conf 
   FILE_LIMITS="/etc/security/limits.conf:*#hard#core#0|/etc/sysctl.conf:fs.suid_dumpable#=#0|EXEC sysctl -w fs.suid_dumpable=0"
   NTP_CONF="restrict -4 default kod nomodify notrap nopeer noquery|restrict -6 default kod nomodify notrap nopeer noquery"
   ################PASS_MIN_DAYS se modifico a pedido de seguridad #########
   LOGINDEF_VALUES="PASS_MAX_DAYS == 30|PASS_MIN_DAYS == 0|UID_MIN == 1000|UID_MAX == 60000"
   PAM_VALUE="minlen=8|dcredit=-2|lcredit=-1|ocredit=-1|ucredit=-1|difok=3|maxrepeats=2"
   SSH_PARAM="Protocol 2|LogLevel INFO|MaxAuthTries 4|IgnoreRhosts yes|HostbasedAuthentication no|PermitRootLogin no|PermitEmptyPasswords no|PermitUserEnvironment no|ClientAliveInterval 1800|ClientAliveCountMax 0|Banner /etc/issue.net|Ciphers aes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128|MACs hmac-sha1,umac-64@openssh.com,hmac-ripemd160|X11Forwarding no|Match address 10.204.167.185,10.204.164.159,10.206.19.47,10.166.13.238,10.166.13.254,10.166.31.102"
   SSH_PARAM_EXEP="ClientAliveInterval 1800"
   GENERAL_PERMS="/etc/crontab chown_root:root chmod_600|/etc/cron.hourly chown_root:root chmod_700_d|/etc/cron.daily chown_root:root chmod_700_d|/etc/cron.weekly chown_root:root chmod_700_d|/etc/cron.monthly chown_root:root chmod_700_d|/etc/cron.d chown_root:root chmod_700_d|/etc/ssh/sshd_config chown_root:root chmod_600|/etc/passwd chown_root:root chmod_644|/etc/shadow chown_root:root chmod_000|/etc/group chown_root:root chmod_644|/etc/gshadow chown_root:root chmod_000"
  ################## MODIFICADO 23/07/2018 pedido de *.info andres #########################
   RSYSLOGD_ATTR="auth.debug  /var/log/authlog chown_root:root|*.info;auth.none   /var/log/syslog chmod_600|*.warn;auth.none    /var/log/messages chmod_640|*.info;mail.none;authpriv.none;cron.none;auth.none  /var/log/messages chmod_640"

   ADM_RAS="/var/adm/ras"
   #SIEM_SERVER="*.* @@10.167.19.57"
   ############### MODIFICADO IEM 28/06/2018 ###########################
   ############### MODIFICADO IEM 13/09/2018 le saque una @ a la linea de server###########################
   SIEM_SERVER="*.* @10.167.19.51"
   TMP_FS_7_FILE=/etc/systemd/system/local-fs.target.wants/tmp.mount
   SERVER_NTP="serve svaix srvrh srvsun:soteclock soteclock2 soteclock3|ct3racp:10.167.144.1|#%:$DEFAULT_GW"
   #SERVICES_DISABLE="avahi-daemon cups dhcpd slapd nfs nfsloc rpcgssd rpcidmapd portmap rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd openldap-servers dhcp net-snmp rsh-server talk-server telnet-server tftp"
   SERVICES_DISABLE="avahi-daemon cups dhcpd slapd portmap named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd openldap-servers dhcp net-snmp rsh-server talk-server telnet-server tftp"
   #SERVICES_REFUSED="httpd nfs rpcbind smb dovecot squid vsftpd nfsloc rpcgssd rpcidmapd portmap"
   SERVICES_REFUSED="httpd smb dovecot squid vsftpd nfsloc portmap"
   SERVICES_ENABLE="auditd rsyslog crond"
   SERVICE_REMOVE="dhcp openldap-servers bind httpd dovecot samba squid net-snmp ypserv rsh-server talk-server telnet-server tftp"
   PACK_NTP="ntp chrony"
   INETD_SERVICES="chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram time-stream tftp"
   PROTOCOL_DISABLE="ipv6 dccp sctp rds tipc"
   BACKUP_LOC=/tmp/sox_tasa/backup
   BACKUP_TARGET=$BACKUP_LOC"/backup_sox_tasa_"$DATE".tar"
   FSTAB=/etc/fstab
   FILESYS="/tmp /home /dev/shm cdrom /var/tmp"
   AUDITFS=/var/log/audit
   AUDITFSSIZE="10G"
   AUDIT_IDENTITY="/etc/group /etc/passwd /etc/shadow /etc/gshadow /etc/security/opasswd /etc/sudoers"
   AUDIT_AUDITING="/etc/audit/audit.rules /etc/audit/auditd.conf /etc/libaudit.conf /etc/sysconfig/auditd /etc/login.defs /etc/security/limits.conf /etc/ssh/sshd_config /etc/rsyslog.conf /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/cron.d/ /etc/crontab"
   NET_DISABLE="net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route"
   NET_ENABLE="net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.tcp_syncookies"


   if [ "$VER" -ge "7" ]
    then
     BACKUP_FILES="$FILE_FS $TMP_FS_7_FILE $FSTAB $FILE_PERMS $FILE_YUM $FILE_GRUB2 $FILE_SYSCTL $FILE_MOTD $FILE_ISSUE $FILE_ISSUE_NET $FILE_INETD $FILE_NTP $FILE_NTP_SYS $FILE_NTP_SERV $FILE_AVAHI $FILE_MAIL7 $FILE_SYSCTL $FILE_AUDIT_RULES $FILE_AUDIT $FILE_RSYSLOGD $FILE_LOGROTATE $FILE_PROFILE $FILE_CRON $FILE_SSH $FILE_SYS_AUTH $FILE_PAM $FILE_SYS_AUTH_AC $FILE_SECURE $FILE_LOGINDEF"
    else
     BACKUP_FILES="$FILE_FS $FSTAB $FILE_PERMS $FILE_YUM $FILE_GRUB $FILE_SYSCTL $FILE_MOTD $FILE_ISSUE $FILE_ISSUE_NET $FILE_INETD $FILE_NTP $FILE_NTP_SYS $FILE_NTP_SERV $FILE_AVAHI $FILE_SENDMAIL $FILE_SYSCTL $FILE_AUDIT_RULES $FILE_AUDIT $FILE_RSYSLOGD $FILE_LOGROTATE $FILE_PROFILE $FILE_CRON $FILE_SSH $FILE_PASS_AUTH $FILE_SYS_AUTH $FILE_PAM $FILE_SYS_AUTH_AC $FILE_SECURE $FILE_LOGINDEF"
    fi
}

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
if [ -f ${SUSER_HOME}/.ssh ]
 then
  echo "${SUSER_HOME}/.ssh EXISTE"
 else
  mkdir -p ${SUSER_HOME}/.ssh
fi
if [ "$KEY_EXT" == "OK" ]
 then
   echo "${SUSER} PUBKEY OK"
 else
   echo "${KPUB}" >>"${SUSER_HOME}/${FILE_AUTH}"
   chmod 640 "${SUSER_HOME}/${FILE_AUTH}"
   chown ${SUSER}:${SUSER} "${SUSER_HOME}/${FILE_AUTH}"
   echo "ACAAAAAAA      chown ${SUSER}:${SUSER} ${SUSER_HOME}/${FILE_AUTH}"
   chmod 750 ${SUSER_HOME}/.ssh
fi
   chmod 640 "${SUSER_HOME}/${FILE_AUTH}"
   chown ${SUSER}:${SUSER} "${SUSER_HOME}/${FILE_AUTH}"
   chmod 750 ${SUSER_HOME}/.ssh
}


backup_action() {
ACTION=$1
mkdir -p "$BACKUP_LOC"

 if [ "$ACTION" == "backup" ]
  then
   tar cvzf $BACKUP_TARGET $BACKUP_FILES 2>/dev/null && echo "BACKUP OK" || echo "BACKUP FAIL"
  else
    if [ "$ACTION" == "restore" ]
      then
       echo "Restoreo de $BACKUP_TARGET"
       ls -ltr $BACKUP_LOC
       echo "Ingrese un file a restorear:"
       read A
       echo "RESTORE FILE: $BACKUP_LOC/$A"
       (cd / ; tar xvzf $BACKUP_LOC/$A ) 2>/dev/null && echo "Restore OK" || echo "Restore FAIL"
      else
       echo "Debe ingresar una opcion: backup o restore"
    fi
 fi
}

ver_dis_fs_prot() {
   # Verifica puntos 7.1.1.1.1/2/3/4/5/6/7 7.3.5.1 7.3.6.1/2/3/4
   echo "################## Verificando puntos 7.1.1.1.1/2/3/4/5/6/7 7.3.5.1 7.3.6.1/2/3/4"
   echo "FSTYPE/NET_PROTOCOL|modprobe|Disable"
   for F in $FS_TYPE $PROTOCOL_DISABLE
    do
     STAT=`modprobe -n -v $F >/dev/null 2>&1 && echo "YES" || echo "NO"`
     if [ -f $FILE_FS ]
      then
       TARGET=`grep $F $FILE_FS >/dev/null 2>&1 && echo "YES" || echo "NO"`
      else
       TARGET="FILE NOT EXIST"
       touch $FILE_FS
     fi
     echo "$F|$STAT|$TARGET"
   done
}


impl_dis_fs_prot() {
   # Implementa puntos 7.1.1.1.1/2/3/4/5/6/7 7.3.5.1 7.3.6.1/2/3/4
   echo "################## Implementando puntos 7.1.1.1.1/2/3/4/5/6/7 7.3.5.1 7.3.6.1/2/3/4"
   for F in $FS_TYPE $PROTOCOL_DISABLE
    do
     if [ -f $FILE_FS ]
      then
       if [ "$F" == "ipv6" ]
        then
           TARGET=`grep $F $FILE_FS|grep "options"|grep "1" >/dev/null 2>&1 && echo "YES" || echo "NO"`
        else
           TARGET=`grep $F $FILE_FS >/dev/null 2>&1 && echo "YES" || echo "NO"`
        fi
       if [ "$TARGET" == "NO" ]
        then
       if [ "$F" == "ipv6" ]
        then
         echo "options $F disable=1" >>$FILE_FS
        else
         echo "install $F /bin/true" >>$FILE_FS
        fi
       fi
      else
       if [ "$F" == "ipv6" ]
        then
         echo "options $F disable=1" >>$FILE_FS
        else
         echo "install $F /bin/true" >>$FILE_FS
        fi
     fi
   done
}

search_fs_infile() {

if [ "$VER" == "7" -a "$FS" == "/tmp" -a -f "$TMP_FS_7_FILE" ]
 then
   VERIF=`grep "Options" $TMP_FS_7_FILE|grep -E 'nodev.*nosuid.*noexec' >/dev/null 2>&1 && echo "OK" || echo "NO_SET"`
 else
    if [ "$FS" == "/home" ]
      then
        VERIF=`grep "$FS " $FSTAB|grep -E "nodev" >/dev/null 2>&1 && echo "OK" || echo "NO_SET"`
      else
        VERIF=`grep "$FS " $FSTAB|grep -E 'nodev.*nosuid.*noexec' >/dev/null 2>&1 && echo "OK" || echo "NO_SET"`
      fi
        if [ "$FS" == "/var" ]
      then
        VERIF=`grep "$FS " $FSTAB|grep " defaults " >/dev/null 2>&1 && echo "OK" || echo "NO_SET"`
      fi

fi
}

verif_fs() {
  #Verifica puntos 7.1.1.2/3/4/5/9/10/14/15/16/17/18/19/20
  echo "################## Verificando puntos 7.1.1.2/3/4/5/9/10/14/15/16/17/18/19/20"
  for FS in $FILESYS
   do
    MOUNT=`mount|grep "$FS " >/dev/null 2>&1 && echo "OK" || echo "NO"`
      if [ "$MOUNT" == "OK" ]
        then
          search_fs_infile
         else
           echo "$FS no es un filesystem"
           BFSTAB=`grep "$FS " $FSTAB >/dev/null 2>&1 && echo "OK" || echo "NO"`
           if [ "$BFSTAB" == "OK" ]
            then
             VERIF="ESTA EN FSTAB NO MONTADO"
            else
             VERIF="NO ESTA EN FSTAB"
            fi
      fi
     echo "$FS Options: $VERIF"
  done
}

impl_fs() {
#Modifica puntos 7.1.1.2/3/4/5/9/10/14/15/16/17/18/19/20
echo "################## Modificando puntos 7.1.1.2/3/4/5/9/10/14/15/16/17/18/19/20"
for FS in $FILESYS
  do
   search_fs_infile
   echo "FS= $FS VERIF= $VERIF"
   if [ "$VER" == "7" -a "$FS" == "/tmp" -a "$VERIF" != "OK" -a -f "$TMP_FS_7_FILE" ]
    then
     CHFS=`sed '/^Options/ s/$/,nodev,nosuid,noexec/' $TMP_FS_7_FILE >$TMP_FS_7_FILE.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
     if [ "$CHFS" == "CH_OK" ]
      then
       mv -f $TMP_FS_7_FILE.tmp $TMP_FS_7_FILE
       mount -o remount ${FS}
      else
       echo "$FS NOT IN $TMP_FS_7_FILE"
     fi
   else
      if [ "$FS" == "/home" -a "$VERIF" != "OK" ]
        then
           CHFS=`awk -v v=$FS ' $2==v { $4=$4",nodev" ;} 1' <$FSTAB >$FSTAB.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
          if [ "$CHFS" == "CH_OK" ]
           then
            mv -f $FSTAB.tmp $FSTAB
            mount -o remount ${FS}
           else
            echo "$FS ERROR NO ESTA EN $FSTAB"
          fi
        else
         if [ "$VERIF" != "OK" ]
          then
           if [ "$FS" == "/var" ]
            then
             CHFS=`awk -v v=$FS ' $2==v { $4="defaults" ;} 1' <$FSTAB >$FSTAB.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
            else
             CHFS=`awk -v v=$FS ' $2==v { $4=$4",nodev,nosuid,noexec" ;} 1' <$FSTAB >$FSTAB.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
           fi
          if [ "$CHFS" == "CH_OK" ]
           then
            mv -f $FSTAB.tmp $FSTAB
            mount -o remount ${FS}
           else
            echo "$FS ERROR in $FSTAB"
          fi
         fi
      fi
   fi
mount -o remount ${FS}
done
}

verif_vg_space() {
#Verifica puntos 7.1.1.2/6/7/11/12
echo "################## Verificando puntos 7.1.1.2/6/7/11/12"
ROOTVG=`grep " / " /etc/fstab|awk '{print $1}'|xargs lvdisplay 2>/dev/null|grep "VG Name"|awk '{print $3}'`
SIZE_MB=`grep " / " /etc/fstab|awk '{print $1}'|xargs lvdisplay 2>/dev/null|grep "VG Name"|awk '{print $3}'|xargs vgdisplay 2>/dev/null|grep "Free  PE / Size"|awk '{print $7}'`
SIZE_TMP=2048
SIZE_VAR=5120
SIZE_LOG=1024
SIZE_AUDIT=10240
echo "$ROOTVG FREE SPACE $SIZE_MB MB"
}

verif_dir_perms() {
#Verifica punto 7.1.1.21
echo "################## Verificando punto 7.1.1.21"
df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
COUNT=`df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null|wc -l`
if [ $COUNT -eq 0 ]
 then
  echo "No hay Directorios que modificar"
fi
}

change_dir_perms() {
#Modifica punto 7.1.1.21
echo "################## Modificando punto 7.1.1.21"
verif_dir_perms >$FILE_PERMS
echo "$COUNT"
if [ $COUNT -gt 0 ]
 then
   IMPL_CHMOD=`df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null|xargs chmod a+t && echo "CHMOD OK" || echo "CHMOD FAILED"`
   echo "$IMPL_CHMOD"
else
   echo "No hay Directorios que modificar"
fi
}

verif_rhn() {
#Verifica punto 7.1.2.1
echo "################## Verificando punto 7.1.2.1"
COUNT=`ps agx 2>/dev/null |grep rhnsd|grep -v grep|wc -l`
if [ "$COUNT" -eq "0" ]
 then
   echo "RHN no configurada consultar administrador"
 else
   echo "RHN esta OK"
fi
}

verif_gpgcheck() {
#Verifica punto 7.1.1.23/24
echo "################## Verificando punto 7.1.1.23/24"
VERIF_GPGCHECK=`grep "gpgcheck=1" $FILE_YUM >/dev/null 2>&1 && echo "GPGCHECK set OK" || echo "GPGCHECK set disable"`
echo $VERIF_GPGCHECK
VERIF_CLAVEGPG=`rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey|grep -v "is not installed"|wc -l`
if [ "$VERIF_CLAVEGPG" -eq "0" ]
 then
  echo "GPG-PUBKEY NO Instalada"
 else
  echo "GPG-PUBKEY OK"
fi
}

impl_gpgcheck() {
#Modifica punto 7.1.1.23/24
echo "################## Modificando punto 7.1.1.23/24"
IMPL_GPGCHECK=`cat $FILE_YUM|sed -e 's/gpgcheck=0/gpgcheck=1/g' >$FILE_YUM.tmp 2>&1 && echo "GPGCHECK set OK" || echo "GPGCHECK set disable"`
if [ "$IMPL_GPGCHECK" == "GPGCHECK set OK" ]
 then
   mv -f $FILE_YUM.tmp $FILE_YUM
 else
   echo "Enable GPGCHECK FAILED"
fi
}

verif_grub() {
#Verifica punto 7.1.3.1
echo "################## Verifica punto 7.1.3.1"

if [ "$VER" -eq "7" ]
 then
  VGRUB=`find $FILE_GRUB2 -perm 0600 -user root -group root|wc -l`
 else
  VGRUB=`find $FILE_GRUB -perm 0600 -user root -group root|wc -l`
fi

if [ "$VGRUB" -eq "0" ]
 then
   echo "GRUB file ERROR"
 else
   echo "GRUB OK"
fi
}

impl_grub() {
#Modifica punto 7.1.3.1
echo "################## Modificando punto 7.1.3.1"
if [ "$VER" -eq "7" ]
 then
  VGRUB_CHMOD=`chmod 600 $FILE_GRUB2 >/dev/null 2>&1 && echo "CHMOD OK" || echo "CHMOD ERROR"`
  VGRUB_CHOWN=`chown root:root $FILE_GRUB2 >/dev/null 2>&1 && echo "CHOWN OK" || echo "CHOWN ERROR"`
 else
  VGRUB_CHMOD=`chmod 600 $FILE_GRUB >/dev/null 2>&1 && echo "CHMOD OK" || echo "CHMOD ERROR"`
  VGRUB_CHOWN=`chown root:root $FILE_GRUB >/dev/null 2>&1 && echo "CHOWN OK" || echo "CHOWN ERROR"`
fi
echo "GRUG $VGRUB_CHMOD|$VGRUB_CHOWN"
} 

verif_sysctl() {
#Modifica punto 7.1.4.2
echo "################## Verficando punto 7.1.4.2"
RND_VA_SPACE_KRNL=`sysctl kernel.randomize_va_space|cut -d"=" -f2|tr -d " "`
RND_VA_SPACE_FILE=`grep kernel.randomize_va_space $FILE_SYSCTL 2>/dev/null|cut -d"=" -f2|tr -d " "`


if [ "$RND_VA_SPACE_KRNL" == "2" ]
  then
   echo "kernel.randomize_va_space KERNEL OK"
  else
   echo "kernel.randomize_va_space KERNEL ERROR"
fi

if [ "$RND_VA_SPACE_FILE" == "2" ]
  then
   echo "kernel.randomize_va_space sysctl.conf OK"
  else
   echo "kernel.randomize_va_space sysctl.conf  ERROR"
fi
}

impl_sysctl() {
#Modifica punto 7.1.4.2
echo "################## Modificando punto 7.1.4.2"
RND_VA_SPACE_FILE=`grep kernel.randomize_va_space $FILE_SYSCTL 2>/dev/null|cut -d"=" -f2|tr -d " "`
if [ "$RND_VA_SPACE_FILE" != "2" -o "$RND_VA_SPACE_FILE" == "" ]
  then
   RND_VA_SPACE_KRNL=`awk '/^kernel.randomize_va_space *=/ { print "kernel.randomize_va_space = 2"; done=1;next } {print} END { if(done != 1) print "kernel.randomize_va_space = 2" }' $FILE_SYSCTL >$FILE_SYSCTL.temp && echo "OK" || echo "ERROR"`
 if [ "$RND_VA_SPACE_KRNL" == "OK" ]
  then
    MV_RND_VA_SPACE_KRNL=`mv -f $FILE_SYSCTL.temp $FILE_SYSCTL >/dev/null 2>&1 && echo "MV OK" ||echo "MV FAIL"`
 fi
    echo "MODIFY $FILE_SYSCTL = $RND_VA_SPACE_KRNL MOVE $FILE_SYSCTL = $MV_RND_VA_SPACE_KRNL"   
else
 echo "kernel.randomize_va_space sysctl.conf  OK"
fi
}

verif_banner() {
#Verifica punto 7.1.5.1
echo "################## Verificando punto 7.1.5.1"

for X in $FILE_MOTD $FILE_ISSUE $FILE_ISSUE_NET
 do
  VERIF_BANN=`grep "Todo uso no autorizado o divulgacion de la informacion de este sistema dara" $X >/dev/null 2>&1 && echo "$X OK" || echo "$X BANNER NO SET"`
  echo "$VERIF_BANN"
done
}


impl_banner() {
#Modifica punto 7.1.5.1
echo "################## Modificando punto 7.1.5.1"
for X in $FILE_MOTD $FILE_ISSUE $FILE_ISSUE_NET
 do
printf "****************************************************************************************\r
*                                                                                      *\r 
*  Todo uso no autorizado o divulgacion de la informacion de este sistema dara         *\r
*  lugar a las medidas legales que correspondan.                                       *\r
*  Las actividades realizadas en este sistema estan auditadas y monitoreadas           *\r
*                                                                                      *\r
****************************************************************************************\n">$X
 chmod 644 $X
 chown root:root $X
done
}	

verif_inetd() {
#Verifica punto 7.2.1.1/2/3/4/5/6
echo "################## Verificando punto 7.2.1.1/2/3/4/5/6"
for SERVICE in $INETD_SERVICES
 do
  INETD_SERV=`chkconfig --list >/dev/null 2>&1|grep "$SERVICE "|grep -i "on" && echo "$SERVICE ON" || echo "$SERVICE OFF"`
  echo "$INETD_SERV"
done
}

impl_inetd() {
#Modifica puntos 7.2.1.1/2/3/4/5/6
echo "################## Modificando puntos 7.2.1.1/2/3/4/5/6"
for SERVICE in $INETD_SERVICES
 do
  INETD_SERV=`chkconfig --list >/dev/null 2>&1|grep "$SERVICE "|grep -i "on" && echo "$SERVICE ON" || echo "$SERVICE OFF"`
  if [ "$INETD_SERV" != "$SERVICE OFF" ]
   then
    CH_INETD=`chkconfig $SERVICE off >/dev/null 2>&1 && echo "DISABLE $SERVICE OK" || echo "DISABLE $SERVICE ERROR"`
    echo "$CH_INETD"
   else
    echo "NO MODIFICADO $INETD_SERV"
  fi
done
}


verif_ntp() {
#Verifica punto 7.2.1.7.1/2
echo "################## Verificando punto 7.2.1.7.1/2"
for PKG in $PACK_NTP
 do
  PKG_INSTALL=`rpm -q $PKG >/dev/null 2>&1 && echo "OK" ||echo "NO"`
  if [ "$PKG_INSTALL" == "OK" -a "$PKG" == "ntp" -a -f "$FILE_NTP" ]
   then
    echo "$PKG $PKG_INSTALL $FILE_NTP ESTA $FILE_NTP_SYS ESTA $FILE_NTP_SERV ESTA"
   else
    if [ "$PKG_INSTALL" == "NO" ]
    then
    echo "$PKG falta paquete instalado"
    else
    echo "$PKG Instalado pero no configurado"
    fi
   fi
done

echo "$NTP_CONF"|tr "|" "\n"|while read NTP_LINE
 do
   NTP_LINE=`echo $NTP_LINE|sed -e 's/ /.*/g'`
   if [ -f "$FILE_NTP" ]
    then
      NTP_SEARCH=`grep "$NTP_LINE" $FILE_NTP >/dev/null 2>&1 && echo "OK" ||echo "NO"`
      echo "$NTP_LINE SETEADO $NTP_SEARCH"
    else
      echo "NO EXISTE EL ARCHIVO FILE_NTP"
   fi
done 

echo "$SERVER_NTP"|tr "|" "\n"|while read line
 do 
  for X in `echo $line|cut -d: -f1`
    do 
    HOST_SEARCH=`echo $HOSTNAME|grep $X >/dev/null 2>&1 && echo "OK" ||echo "NO"`
    if [ "$HOST_SEARCH" == "OK" ]
     then
      for SRV in `echo $line|cut -d: -f2`
       do
        SRV_SEARCH=`grep -i server $NTP_LINE|grep $SRV >/dev/null 2>&1 && echo "OK" ||echo "NO"`
        echo "$NTP_LINE SET SERVER $SRV $SRV_SEARCH"
      done
    else
     if [ "$X" == "#%" ]
      then
        echo "ENTREE"
        SRV_SEARCH=`grep -i server $NTP_LINE|grep "$DEFAULT_GW" >/dev/null 2>&1 && echo "OK" ||echo "NO"` 
        echo "$NTP_LINE SET SERVER $SRV_SEARCH"
     fi
    fi
 done 
done
}

impl_ntp() {
#Modifica punto 7.2.1.7.1/2
echo "################## Modifica punto 7.2.1.7.1/2"
echo "Verificar NTP template"
MOVE_CONF=`sed -e 's/restrict*./#restrict*./g' -e 's/server*./#server*./g' $FILE_NTP >$FILE_NTP.tmp`

echo "$NTP_CONF"|tr "|" "\n"|while read NTP_LINE
 do
   if [ -f "$FILE_NTP" ]
    then
      NTP_MODIF=`echo "$NTP_LINE" >>$FILE_NTP.tmp && echo "OK" ||echo "NO"`
      echo "$NTP_LINE SETEADO $NTP_MODIF"
    else
      echo "NO EXISTE EL ARCHIVO FILE_NTP"
   fi
done
SET_COUNT=0
echo "$SERVER_NTP"|tr "|" "\n"|while read line 
do
 for X in `echo $line|cut -d: -f1`
  do
    HOST_SEARCH=`echo $HOSTNAME|grep -i "^$X" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
    echo "$HOST_SEARCH"
    if [ "$HOST_SEARCH" == "OK" ]
     then
      for SRV in `echo $line|cut -d: -f2`
       do
        NTP_MODIF=`echo "server $SRV" >>$FILE_NTP.tmp && echo "OK" ||echo "NO"`
        echo "$NTP_LINE SET SERVER $SRV $SRV_MODIF"
        SET_COUNT=1
      done
    else
     if [ "$X" == "#%" -a "$HOST_SEARCH" == "NO" -a "$SET_COUNT" -eq "0" ]
      then
        echo "ENTREEEE $X $HOST_SEARCH"
        NTP_MODIF=`echo "server $DEFAULT_GW" >>$FILE_NTP.tmp && echo "OK" ||echo "NO"`
        echo "$NTP_LINE SET SERVER $DEFAULT_GW $SRV_MODIF"
     fi
    fi
 done
done
mv -f $FILE_NTP.tmp $FILE_NTP
}


verif_X() {
#Verifica punto 7.2.1.8
echo "################## Verifica punto 7.2.1.8"
echo "X NO APLICA"
}

impl_X() {
#Modifica punto 7.2.1.8
echo "################## Modifica punto 7.2.1.8"
echo "X NO APLICA"
}

verif_services() {
#Verfica punto 7.2.2.3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21
echo "################## Verifica punto 7.2.2.3/4/5/6/7/8/9/10/11/12/13/14/15/16/17/18/19/20/21" 
for LSERV in $SERVICES_DISABLE $SERVICES_ENABLE
 do
   if [ "$VER" -ne "7" ]
    then
     SERV_STAT=`chkconfig --list $LSERV 2>/dev/null|grep ":on" >/dev/null 2>&1 && echo "UP" ||echo "DOWN"`
     echo "$LSERV $SERV_STAT"
   else
     SERV_STAT=`systemctl is-enabled $LSERV 2>/dev/null|grep -i "enabled" >/dev/null 2>&1 && echo "UP" ||echo "DOWN"`
     echo "$LSERV $SERV_STAT"
  fi
done
}

impl_services() {
#Modifica punto 7.2.2.3/4/5/6/7/8/9/10/11/12/13/14/16/17/18/19/20/21
echo "################## Modifica punto 7.2.2.3/4/5/6/7/8/9/10/11/12/13/14/16/17/18/19/20/21" 

for LSERV in $SERVICES_DISABLE 
 do
  REFUSED=`echo $SERVICES_REFUSED|grep $LSERV >/dev/null 2>&1 && echo "YES" ||echo "NO"`
  if [ "$REFUSED" == "NO" ]
   then
   if [ "$VER" -ne "7" ]
     then
       SERV_STOP=`service $LSERV stop >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$LSERV STOP $SERV_STOP"
       SERV_DISABLE=`chkconfig $LSERV off >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$LSERV DISABLE $SERV_DISABLE"
       YUM_REMOVE=`echo "$SERVICE_REMOVE"|grep "$LSERV" >/dev/null 2>&1 && echo "YES" ||echo "NO"`
       if [ "$YUM_REMOVE" == "YES" ]
        then
          echo "################ yum erase $LSERV"
        fi
     else
       SERV_STOP=`systemctl stop $LSERV >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$LSERV STOP $SERV_STOP"
       SERV_DISABLE=`systemctl disable $LSERV >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$LSERV DISABLE $SERV_DISABLE"
       #AVAHI_MASK=`systemctl mask avahi-daemon.socket avahi-daemon.service >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       #echo "AVAHI MASK $AVAHI_MASK"
   fi
   if [ "$LSERV" == "avahi-daemon" ]
     then
       echo "AVAHI_DAEMON_START = 0" >/etc/default/avahi-daemon
   fi
  else
    echo "$LSERV NO SE DESHABILITA CONSULTAR DOCUMENTACION"
  fi
done
for ESERV in $SERVICES_ENABLE
 do
     if [ "$VER" -ne "7" ]
     then
       SERV_START=`service $ESERV start >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$ESERV START $SERV_START"
       SERV_ENABLE=`chkconfig $ESERV on >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$ESERV ENABLE $SERV_ENABLE"
     else
       SERV_START=`systemctl start $ESERV  >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$ESERV START $SERV_START"
       SERV_ENABLE=`systemctl enable $ESERV >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$ESERV ENABLE $SERV_ENABLE"
   fi
done
}

verif_mail() {
#Verifica punto 7.2.2.3.15
echo "################## Verifica punto 7.2.2.3.15"
MAIL_SERV=`netstat -an | grep LIST | grep ":25[[:space:]]" >/dev/null && echo "UP" || echo "DOWN"`
echo "MAILSERVER $MAIL_SERV"
if [ "$VER" -ne "7" ]
  then
   SENDMAIL_CF=`grep "O DaemonPortOptions=Port=smtp,Addr=127.0.0.1," $FILE_SENDMAIL|grep "Name=MTA" >/dev/null && echo "OK" || echo "NO"`
   echo "MAILSERVER LOCAL $SENDMAIL_CF"
  else
   SENDMAIL_CF=`grep "^inet_interfaces" $FILE_MAIL7|grep "localhost" >/dev/null && echo "OK" || echo "NO"`
   echo "MAILSERVER LOCAL $SENDMAIL_CF"
fi
}

impl_mail() {
#Modifica punto 7.2.2.3.15
echo "################## Modifica punto 7.2.2.3.15"
echo "NO SE MODIFICA CONSULTAR DOCIMENTACION"
}

verif_net(){
#Verifica punto 7.3.1.1/2/3/4/5/6/7/
echo "################## Verifica punto 7.3."
for VAR in $NET_DISABLE
 do
   NET_VALUE=`/sbin/sysctl $VAR|grep "= 0" >/dev/null && echo "OK" || echo "NO"`
   echo "$VAR SET $NET_VALUE"
done

for VAR in $NET_ENABLE
 do
   NET_VALUE=`/sbin/sysctl $VAR|grep "= 1" >/dev/null && echo "OK" || echo "NO"`
   echo "$VAR SET $NET_VALUE"
done
}


impl_net(){
#Modifica punto 7.3
echo "################## Modifica punto 7.3."
for VAR in $NET_DISABLE
 do
   NET_VALUE=`/sbin/sysctl -w "$VAR"=0 >/dev/null && echo "OK" || echo "NO"`
   NET_SYSCTL=`cat $FILE_SYSCTL|sed '1{p;s~.*~'$VAR'=0~;h;d};/^.*'$VAR'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_SYSCTL.tmp && echo "OK" ||echo "ERROR"`
   mv -f $FILE_SYSCTL.tmp $FILE_SYSCTL
   echo "$VAR SET $NET_VALUE SYSCTL.CONF $NET_SYSCTL"
done

for VAR in $NET_ENABLE
 do
   NET_VALUE=`/sbin/sysctl -w "$VAR"=1 >/dev/null && echo "OK" || echo "NO"`
   NET_SYSCTL=`cat $FILE_SYSCTL|sed '1{p;s~.*~'$VAR'=1~;h;d};/^.*'$VAR'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_SYSCTL.tmp && echo "OK" ||echo "ERROR"`
   mv -f $FILE_SYSCTL.tmp $FILE_SYSCTL
   echo "$VAR SET $NET_VALUE"
done
  FLUSH=`/sbin/sysctl -w net.ipv4.route.flush=1 >/dev/null && echo "OK" || echo "NO"`
  echo "FLUSH $FLUSH"
}

verif_wireless() {
#Verifica punto 7.3.3
echo "################## Verifica punto 7.3.3"
WL_DEVICE=`ifconfig -a|grep "^wl"|awk '{print $1}'|cut -d: -f1`
if [ "$WL_DEVICE" != "" ]
 then
  WL_STATE=`ifconfig $WL_DEVICE|grep "UP" >/dev/null && echo "UP" || echo "DOWN"`
  WL_IP=`ifconfig $WL_DEVICE|grep "inet "|awk '{print $2}'`
fi
echo "WIRELESS $WL_DEVICE $WL_STATE $WL_IP"
}

impl_wireless() {
#Modifica punto 7.3.3
echo "################## Modifica punto 7.3.3"
WL_DEVICE=`ifconfig -a|grep "^wl"|awk '{print $1}'|cut -d: -f1`
if [ "$WL_DEVICE" != "" ]
 then
  WL_STATE=`ifconfig $WL_DEVICE|grep "UP" >/dev/null && echo "UP" || echo "DOWN"`
  WL_IP=`ifconfig $WL_DEVICE|grep "inet "|awk '{print $2}'`
  echo "ifdown WL_DEVICE"
  echo "rm /etc/sysconfig/network-scripts/ifcfg-$WL_DEVICE"
fi
echo "WIRELESS $WL_DEVICE $WL_STATE $WL_IP"
}

verif_audit() {
#Modifica punto 7.4.1.2
echo "################## Modifica punto 7.4.1.2"
AUDIT_SIZE_LOG=`grep "max_log_file " $FILE_AUDIT|awk '{print $3}'`
if [ "$AUDIT_SIZE_LOG" -lt "100" ]
 then
   echo "Audit max_log_file es menor que lo requerido: $AUDIT_SIZE_LOG"
 else
   echo "Audit max_log_file OK $AUDIT_SIZE_LOG"
fi
}

impl_audit() {
#Modifica punto 7.4.1.2
echo "################## Modifica punto 7.4.1.2"
AUDIT_SIZE_LOG=`grep "max_log_file " $FILE_AUDIT|awk '{print $3}'`
if [ "$AUDIT_SIZE_LOG" -le "100" ]
 then
   AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/max_log_file =.*/max_log_file = 100/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
   if [ "$AUDIT_MODIF" == "OK" ]
    then
     AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
     echo "Modificacion $FILE_AUDIT $AUDIT_MODIF $AUDIT_MOVE"
    else
     echo "Modificacion $FILE_AUDIT $AUDIT_MODIF"
   fi
 else
   echo "Audit max_log_file OK $AUDIT_SIZE_LOG NO modificado"
fi
}

verif_audit_rules() {
#Verifica punto 7.4.1.1
echo "################## Verifica punto 7.4.1.1"
if [ -f "$FILE_AUDIT_RULES" ]
then
for ALINE in $AUDIT_IDENTITY 
 do
  EXIST=`grep "$ALINE" $FILE_AUDIT_RULES|grep "identity"|grep "\-p wa \-k" >/dev/null 2>&1 && echo "OK" || echo "NO"`
  if [ "$EXIST" != "OK" ]
  then
  echo "NO EXISTE LA LINEA \"-w $ALINE -p wa -k identity\""
  else
  echo "$ALINE Existe en $FILE_AUDIT_RULES. NO SE MODIFICA"
  fi
 done

for ALINE in $AUDIT_AUDITING
 do
 EXIST=`grep "$ALINE" $FILE_AUDIT_RULES|grep "auditing"|grep "\-p wa \-k" >/dev/null 2>&1 && echo "OK" || echo "NO"`
  if [ "$EXIST" != "OK" ]
  then
  echo "NO EXISTE LA LINEA \"-w $ALINE -p wa -k auditing\"" 
  else
  echo "$ALINE Existe en $FILE_AUDIT_RULES. NO SE MODIFICA"
  fi
 done
else
 echo "$FILE_AUDIT_RULES NO EXISTE"
fi
}


impl_audit_rules() {
#Modifica punto 7.4.1.1
echo "################## Modifica punto 7.4.1.1"
if [ -f "$FILE_AUDIT_RULES" ]
then
for ALINE in $AUDIT_IDENTITY
 do
  EXIST=`grep "$ALINE" $FILE_AUDIT_RULES|grep identity|grep "\-p wa \-k" >/dev/null 2>&1 && echo "OK" || echo "NO"`
  if [ "$EXIST" != "OK" ]
  then
  echo "-w $ALINE -p wa -k identity" >>$FILE_AUDIT_RULES
  else
  echo "$ALINE Existe en $FILE_AUDIT_RULES. NO modificado"
  fi
 done

for ALINE in $AUDIT_AUDITING
 do
 EXIST=`grep "$ALINE" $FILE_AUDIT_RULES|grep auditing|grep "\-p wa \-k" >/dev/null 2>&1 && echo "OK" || echo "NO"`
  if [ "$EXIST" != "OK" ]
  then
  echo "-w $ALINE -p wa -k auditing" >>$FILE_AUDIT_RULES
  else
  echo "$ALINE Existe en $FILE_AUDIT_RULES. NO modificado"
  fi
 done
else
 echo "$FILE_AUDIT_RULES NO EXISTE"
fi
 cp -f $FILE_AUDIT_RULES /etc/audit/rules.d/
}

verif_rsyslog() {
#Verifica punto 7.4.1.1
echo "################## Verificando punto 7.4.1.1"
echo "$RSYSLOGD_ATTR"| tr "|" "\n"|while read ATTR
 do
  MODULE=`echo $ATTR|awk '{print $1}'|tr -d "\n"`
  MODULE_FILE=`echo $ATTR|awk '{print $2}'|tr -d "\n"`
  MODULE_PERMS=`echo $ATTR|awk '{print $3}'|tr "_" " "`
  COMM_MODULE=`echo $MODULE_PERMS|awk '{print $1}'`
  if [ -f $MODULE_FILE ]
  then
  if [ "$COMM_MODULE" == "chown" ]
   then
    USER=`echo "$MODULE_PERMS"|awk '{print $2}'|cut -d":" -f1`
    GROUP=`echo "$MODULE_PERMS"|awk '{print $2}'|cut -d":" -f2`
    PERM_FILE=`find $MODULE_FILE -user $USER -group $GROUP && echo "OK" ||echo "ERROR"`
    echo "$MODULE_FILE perms $MODULE_PERMS $PERM_FILE"
   else
    MODE=`echo "$MODULE_PERMS"|awk '{print $2}'`
    PERM_FILE=`find $MODULE_FILE -perm $MODE && echo "OK" ||echo "ERROR"`
    echo "$MODULE_FILE perms $PERM_FILE"
   fi
  VERIF_MODULE_AUTH=`grep "$MODULE" $FILE_RSYSLOGD|grep "$MODULE_FILE" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
  
  if [ "$VERIF_MODULE_AUTH" == "NO" ]
  then
    echo "$MODULE  $MODULE_FILE NO ESTA EN $FILE_RSYSLOGD"
  else
    echo "$MODULE  $MODULE_FILE ESTA CONFIGURADO EN $FILE_RSYSLOGD"
  fi 

  else
  echo "$MODULE_FILE NO EXISTE"
  fi
done
VERIF_SIEM=`grep "^*.*[^I][^I]*@" $FILE_RSYSLOGD|grep "$SIEM_SERVER" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
if [ "$VERIF_SIEM" == "NO" ]
 then
   echo "SIEM SERVER NO ESTA CONFIGURADO EN $FILE_RSYSLOGD"
 else
   echo "$SIEM_SERVER ESTA CONFIGURADO EN $FILE_RSYSLOGD"
fi

}


impl_rsyslog() {
#Modifica punto 7.4.1.1
echo "################## Modifica punto 7.4.1.1"
echo "$RSYSLOGD_ATTR"| tr "|" "\n"|while read ATTR
 do
  MODULE=`echo $ATTR|awk '{print $1}'`
  MODULE_FILE=`echo $ATTR|awk '{print $2}'`
  MODULE_PERMS=`echo $ATTR|awk '{print $3}'|tr "_" " "`
  COMM_MODULE=`echo $MODULE_PERMS|awk '{print $1}'`

  echo "$MODULE_PERMS $MODULE_FILE"
  if [ ! -f "$MODULE_FILE" ]
   then
     touch $MODULE_FILE
   fi
  if [ "$COMM_MODULE" == "chown" ]
      then
       USER=`echo "$MODULE_PERMS"|awk '{print $2}'|cut -d":" -f1`
       GROUP=`echo "$MODULE_PERMS"|awk '{print $2}'|cut -d":" -f2`
       PERM_FILE=`$COMM_MODULE $USER:$GROUP $MODULE_FILE && echo "OK" ||echo "ERROR"`
       echo "$MODULE_FILE perms $MODULE_PERMS change $PERM_FILE"
      else
       MODE=`echo "$MODULE_PERMS"|awk '{print $2}'`
       PERM_FILE=`$COMM_MODULE $MODE $MODULE_FILE && echo "OK" ||echo "ERROR"`
       echo "$MODULE_FILE perms $PERM_FILE change $PERM_FILE"
    fi

  VERIF_MODULE_AUTH=`grep "$MODULE" $FILE_RSYSLOGD|grep "$MODULE_FILE" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
  if [ "$VERIF_MODULE_AUTH" == "NO" ]
  then
    MODIF_RSYSLOG=`echo "$MODULE     $MODULE_FILE" >>$FILE_RSYSLOGD 2>/dev/null && echo "OK" || echo "ERROR"`
    echo "$MODULE     $MODULE_FILE ADD $FILE_RSYSLOGD $MODIF_RSYSLOG"
  else
    echo "$MODULE  $MODULE_FILE ESTA CONFIGURADO EN $FILE_RSYSLOGD"
  fi
done
   VERIF_SIEM=`grep "^*.*[^I][^I]*@@" $FILE_RSYSLOGD|grep "$SIEM_SERVER" >/dev/null 2>&1 && echo "OK" ||echo "NO"`
   if [ "$VERIF_SIEM" == "NO" ]
  then
   #### MODIFICADO PORQUE ALGUNOS NO LOGEAN LOCALMENTE DESPUES DE LA MODIF
    echo "$SIEM_SERVER ESTA CONFIGURADO EN $FILE_RSYSLOGD"
    grep -vE '^*.*[^I][^I]*@@|^\$ActionQueueType LinkedList|^\$ActionResumeRetryCount -1' $FILE_RSYSLOGD >/tmp/rsyslogd.conf.tmp
    #### MODIFICADO PORQUE ALGUNOS NO LOGEAN LOCALMENTE DESPUES DE LA MODIF
    echo "# SOX Modificacion envio a server remoto" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionQueueType LinkedList   # run asynchronously" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionResumeRetryCount -1    # infinite retries if host is down" >>/tmp/rsyslogd.conf.tmp
    echo "$SIEM_SERVER" >>/tmp/rsyslogd.conf.tmp
    cp -f /tmp/rsyslogd.conf.tmp $FILE_RSYSLOGD
  else
    echo "$SIEM_SERVER ESTA CONFIGURADO EN $FILE_RSYSLOGD"
    grep -vE '^*.*[^I][^I]*@@|^\$ActionQueueType LinkedList|^\$ActionResumeRetryCount -1' $FILE_RSYSLOGD >/tmp/rsyslogd.conf.tmp
    #### MODIFICADO PORQUE ALGUNOS NO LOGEAN LOCALMENTE DESPUES DE LA MODIF
    echo "# SOX Modificacion envio a server remoto" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionQueueType LinkedList   # run asynchronously" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionResumeRetryCount -1    # infinite retries if host is down" >>/tmp/rsyslogd.conf.tmp
    echo "$SIEM_SERVER" >>/tmp/rsyslogd.conf.tmp
    cp -f /tmp/rsyslogd.conf.tmp $FILE_RSYSLOGD
  fi
#### Restart rsyslogd
echo "#### Restating syslogd"
service rsyslog stop;sleep 5;service rsyslog start
service syslog stop;sleep 5;service syslog start
}

verif_logrotate() {
#Verifica punto 7.4.3
echo "################## Verifica punto 7.4.3"
COUNT=0
for LOG in $FILE_SYSLOG
 do
  VERIF_LOG=`grep "$LOG" $FILE_LOGROTATE >/dev/null 2>&1 && echo "1" ||echo "0"`
  COUNT=`expr "$COUNT" + "$VERIF_LOG"`
done
  if [ "$COUNT" -lt "7" ]
   then
     echo "$FILE_LOGROTATE ESTA INCOMPLETO"
   else
     echo "$FILE_LOGROTATE ESTA OK"
  fi
}

impl_logrotate() {
#Modifica punto 7.4.3
echo "################## Modifica punto 7.4.3"
mv -f $FILE_LOGROTATE $FILE_LOGROTATE.old
echo "mv -f $FILE_LOGROTATE $FILE_LOGROTATE.old"
for LOG in $FILE_SYSLOG
do
 echo "$LOG" >>$FILE_LOGROTATE
done
echo "{" >>$FILE_LOGROTATE
echo "    weekly" >>$FILE_LOGROTATE
echo "    maxsize 300M " >>$FILE_LOGROTATE
echo "    rotate 12" >>$FILE_LOGROTATE
echo "    missingok" >>$FILE_LOGROTATE
echo "    sharedscripts" >>$FILE_LOGROTATE
echo "    compress" >>$FILE_LOGROTATE
echo "    postrotate" >>$FILE_LOGROTATE
echo "    /bin/kill -HUP \`cat /var/run/syslogd.pid 2> /dev/null\` 2> /dev/null || true" >>$FILE_LOGROTATE
echo "    endscript" >>$FILE_LOGROTATE
echo "}" >>$FILE_LOGROTATE
}

verif_history(){
#Verifica punto 7.5
echo "################## Verfica punto 7.5"
VERIF_PROFILE1=`grep "Capture shell history" $FILE_PROFILE >/dev/null 2>&1 && echo "OK" ||echo "NO"`
VERIF_PROFILE2=`grep "HISTSIZE=2048" $FILE_PROFILE >/dev/null 2>&1 && echo "OK" ||echo "NO"`
if [ "$VERIF_PROFILE1" != "OK" -a "VERIF_PROFILE2" != "OK" ]
 then
   echo "PROFILE $FILE_PROFILE NO Configurado"
 else
  echo "PROFILE $FILE_PROFILE OK"
fi
}

impl_history(){
#Modifica punto 7.5.1
echo "################## Modifica punto 7.5.1"
mkdir -p /var/log/hist 2>/dev/null
chmod 777 /var/log/hist 2>/dev/null
chmod o+t /var/log/hist 2>/dev/null
chown root:root /var/log/hist 2>/dev/null
VERIF_HIS=`grep "Capture shell history" $FILE_PROFILE|grep "HISTSIZE=2048">/dev/null 2>&1 && echo "OK" ||echo "NO"`
if [ "$VERIF_HIS" != "OK" ]
then
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
  echo "PROFILE YA ESTA CONFIGURADO"
fi
}


verif_cron() {
#Verifica punto 7.5.2.0/1/2/3/4/5/6/7 7.6.1/2/3/4/5
echo "################## Verifica punto 7.5.2.0/1/2/3/4/5/6/7  7.6.1/2/3/4/5"
echo "$GENERAL_PERMS"| tr "|" "\n"|while read ATTR_CRON
 do
  FILE_CR=`echo $ATTR_CRON|awk '{print $1}'`
  FILE_CR_CHOWN=`echo $ATTR_CRON|awk '{print $2}'|tr "_" " "`
  FILE_CR_CHMOD=`echo $ATTR_CRON|awk '{print $3}'|tr "_" " "`
  CHOWN_ATTR=`echo $FILE_CR_CHOWN|awk '{print $2}'|tr "_" " "`
  CHMOD_ATTR=`echo $FILE_CR_CHMOD|awk '{print $2}'|tr "_" " "`
  T=`echo $FILE_CR_CHMOD|awk '{print $3}'|tr "_" " "`
  if [ "$T" == "" ]
  then
    T=f
  fi
  USER=`echo $CHOWN_ATTR|cut -d":" -f1`
  GROUP=`echo $CHOWN_ATTR|cut -d":" -f2`
  if [ -f $FILE_CR -o -d $FILE_CR ]
  then
    PERM_FILE=`find $FILE_CR -type "$T" -user $USER -group $GROUP`
    if [ "$PERM_FILE" == "" ]
    then
      PERM_FILE="ERROR"
    else
      PERM_FILE="OK"
    fi
    echo "$FILE_CR OWNER $CHOWN_ATTR $PERM_FILE"
    PERM_FILE=`find $FILE_CR -type "$T" -perm $CHMOD_ATTR`
    if [ "$PERM_FILE" == "" ]
    then
      PERM_FILE="ERROR"
    else
      PERM_FILE="OK"
    fi
    echo "$FILE_CR PERMS $CHMOD_ATTR $PERM_FILE"
   else
    echo "$FILE_CR NO EXISTE"
  fi
done
}


impl_cron() {
#Modifica punto 7.5.2.0/1/2/3/4/5/6/7  7.6.1/2/3/4/5
echo "################## Modifica punto 7.5.2.0/1/2/3/4/5/6/7  7.6.1/2/3/4/5"
echo "$GENERAL_PERMS"| tr "|" "\n"|while read ATTR_CRON
 do
  FILE_CR=`echo $ATTR_CRON|awk '{print $1}'`
  FILE_CR_CHOWN=`echo $ATTR_CRON|awk '{print $2}'|tr "_" " "`
  FILE_CR_CHMOD=`echo $ATTR_CRON|awk '{print $3}'|tr "_" " "`
  CHOWN_ATTR=`echo $FILE_CR_CHOWN|awk '{print $2}'|tr "_" " "`
  CHMOD_ATTR=`echo $FILE_CR_CHMOD|awk '{print $2}'|tr "_" " "`
  T=`echo $FILE_CR_CHMOD|awk '{print $3}'|tr "_" " "`
    if [ "$T" == "" ]
  then
    T=f
  fi
  USER=`echo $CHOWN_ATTR|cut -d":" -f1`
  GROUP=`echo $CHOWN_ATTR|cut -d":" -f2`

  if [ -f $FILE_CR -o -d $FILE_CR ]
  then
    PERM_FILE=`find $FILE_CR -type $T -user $USER -group $GROUP`
    if [ "$PERM_FILE" == "" ]
    then
      PERM_FILE="ERROR"
    else
      PERM_FILE="OK"
    fi
    if [ "$PERM_FILE" != "OK" ]
    then
      CHOWN=`chown $USER:$GROUP $FILE_CR 2>/dev/null && echo "OK" ||echo "ERROR"`
      echo "$FILE_CR CHOWN $CHOWN"
    else
      echo "$FILE_CR CHOWN OK"
    fi
    PERM_FILE=`find $FILE_CR -type $T -perm $CHMOD_ATTR`
    if [ "$PERM_FILE" == "" ]
    then
      PERM_FILE="ERROR"
    else
      PERM_FILE="OK"
    fi
    if [ "$PERM_FILE" != "OK" ]
    then
      CHMOD=`chmod $CHMOD_ATTR $FILE_CR 2>/dev/null && echo "OK" ||echo "ERROR"`
      echo "$FILE_CR CHMOD $CHMOD"
    else
      echo "$FILE_CR CHMOD OK"
    fi
   else
    echo "$FILE_CR NO EXISTE"
  fi
done
}

spkey_ibmunx() {
KIBMUNX="ssh-dss AAAAB3NzaC1kc3MAAACBANtKI2IlMM63qshnj1E5Qubvke/yn/qkV3fkUecDCLDGuA09R5YxKrY833DjykbNna0FRDpc0WhA0GBbPRgCvK55L44TM7nUKgfG1m+M14ps6KEYnaHf8U8LR0CGuRA5rf3HScqHpvl89CYBivedWOFEgD8XCXtEQ5h9So/WgKdPAAAAFQDXEHid2tjCEpAofya/0ipEzpf8DwAAAIBKzwBltdlo95b5hqN6aGZVKYZqfMwKQeoqTBzqdz+CJLU/dPobDMBplNXLBSY0sU5qLjvQiLFZdg4rJTIbQBfp+G+jBGaAQwuFc47OAv4RPMKc79enPHeE8rR0iO5foD12EqKEpZlT1mc8Rz0NzWSpcQOi9KQehok29EaQ/BfWEgAAAIB/4Vqc2IZzppuLurM0NG3vpwv22LRAi9aiuObtZuu24iRtZ8RmVBqij7g95SC1RfcOucAMfrHsLq0xOgwt5rMwl274jG3hwre0KISV9fpyVvV8ECPh6o2rIkUHdvGv4Hy6bAEWXKUAI27cW5UX/RFXITlJxga4uIB840XYfEyGIw== root@bastionamdocs"
SUSER="ibmunx"
FILE_AUTH=".ssh/authorized_keys"
SUSER_HOME=`grep ${SUSER} /etc/passwd|cut -d":" -f6`
}


verif_ibmunx_user() {
   spkey_ibmunx
   USERI=`cat /etc/passwd|grep ibmunx >/dev/null 2>&1 && echo "ibmunx:OK" || echo "ibmunx:NO_EXISTE"`
   KEYI=`grep "${KIBMUNX}" /home/ibmunx/.ssh/authorized_keys  >/dev/null  2>&1 && echo "ibmunx_key:OK" || echo "ibmunx_key:NO_EXISTE"`
   SRV_K=`uname -n`
   echo "$SRV_K|$USERI|$KEYI"
}

impl_ibmunx() {
  verif_ibmunx_user
  if [ "$USERI" == "ibmunx:NO_EXISTE" ]
   then
    useradd -d /home/ibmunx -m -s /bin/bash -g ibmunx ibmunx && mkdir -p /home/ibmunx/.ssh && chage -M -1 ibmunx && chmod 750 /home/ibmunx/.ssh && echo "${KIBMUNX}" >/home/ibmunx/.ssh/authorized_keys && chown -R ibmunx:ibmunx /home/ibmunx/.ssh && chmod 640 /home/ibmunx/.ssh/authorized_keys
  else
    if [ "$KEYI" == "ibmunx_key:NO_EXISTE" ]
     then
       chage -M -1 ibmunx
       mkdir -p /home/ibmunx/.ssh && chmod 750 /home/ibmunx/.ssh && echo "${KIBMUNX}" >/home/ibmunx/.ssh/authorized_keys && chown -R ibmunx:ibmunx /home/ibmunx/.ssh && chmod 640 /home/ibmunx/.ssh/authorized_keys
     fi
  fi
  chown ibmunx:ibmunx /home/ibmunx/.ssh/authorized_keys
} 
    
verif_ssh(){
#Verifica punto 7.5.3
echo "################## Modifica punto 7.5.3"
verif_ibmunx_user
echo "$SSH_PARAM"| tr "|" "\n"|while read SSH_LINE
 do
  SSH_VALUE=`grep "^$SSH_LINE" $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$SSH_LINE $SSH_VALUE"
done
echo "################# Chequeando valores del TEAM de seguridad"
echo "$SSH_SEC_PARAM"| tr "|" "\n"|while read SSH_LINE
 do
  SSH_VALUE=`grep "^$SSH_LINE" $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$SSH_LINE $SSH_VALUE"
done
}

impl_ssh(){
#Modifica punto 7.5.3
echo "################## Modifica punto 7.5.3"
verif_ibmunx_user
if [ "$USERI" == "ibmunx:NO_EXISTE" -o "$KEYI"=="ibmunx_key:NO_EXISTE" ]
 then
 SSH_PARAM_EXEP="ClientAliveInterval 1800"
fi

echo "$SSH_PARAM"| tr "|" "\n"|while read SSH_LINE
 do
  echo "$SSH_PARAM_EXEP"| tr "|" "\n"|while read SSH_LINE_EXEP
  do
  SSH_VARIABLE_EXEP=`echo $SSH_LINE_EXEP|awk '{print $1}'`
  SSH_SET_EXEP=`echo $SSH_LINE_EXEP|awk '{print $2}'`
  SSH_VARIABLE=`echo $SSH_LINE|awk '{print $1}'`
  SSH_A_SET=`grep "^$SSH_VARIABLE" $FILE_SSH|awk '{print $2}'`
  #echo "$SSH_VARIABLE_EXEP $SSH_SET_EXEP $SSH_VARIABLE $SSH_SET"
  if [ "$SSH_VARIABLE" == "$SSH_VARIABLE_EXEP" -a "$SSH_A_SET" == "$SSH_SET_EXEP" ]
  then
   echo "$SSH_VARIABLE_EXEP $SSH_SET_EXEP SE IGNORA POR PEDIDO"
  else
  SSH_SET=`echo $SSH_LINE|awk '{print $2}'`
  SSH_CHANGE=`cat $FILE_SSH|sed '1{p;s~.*~'$SSH_VARIABLE' '$SSH_SET'~;h;d};/^.*'$SSH_VARIABLE'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_SSH.tmp && echo "OK" ||echo "ERROR"`
  SSH_MOVE=`mv -f $FILE_SSH.tmp $FILE_SSH`
  SSH_CHMOD=`chmod og-rwx $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$FILE_SSH CHMOD $SSH_CHMOD"
  SSH_VALUE=`grep "^$SSH_LINE" $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
  echo "$SSH_VARIABLE CAMBIO $SSH_CHANGE"
  fi
 done
done
SSH_SEC_PARAM="Match address 10.204.167.185,10.204.164.159,10.206.19.47,10.166.13.238,10.166.13.254,10.166.31.102|\"$(printf '\t') PermitRootLogin yes\""
VERIF_SEC=`grep -A2 "Match address 10.204.167.185,10.204.164.159,10.206.19.47,10.166.13.238,10.166.13.254,10.166.31.102" $FILE_SSH|wc -l`
if [ "$VERIF_SEC" -le "1" ]
 then
 cat $FILE_SSH |grep -v "Match address" >$FILE_SSH.tmp
 echo "$SSH_SEC_PARAM"|tr "|" "\n"|while read LINE
 do
  printf "$LINE\n"|tr -d "\"" >>$FILE_SSH.tmp
 done
 mv $FILE_SSH.tmp $FILE_SSH
 SSH_CHMOD=`chmod og-rwx $FILE_SSH >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
else
echo "SSH_SEC_PARAM OK"
fi

service sshd restart
}

template_system_auth_5(){
echo "#%PAM-1.0"
echo "auth        required      pam_env.so"
echo "auth        required      pam_tally2.so deny=5 onerr=fail"
echo "auth        sufficient    pam_unix.so nullok try_first_pass"
echo "auth        requisite     pam_succeed_if.so uid >= 500 quiet"
echo "auth        required      pam_deny.so"
echo ""
echo "account     required      pam_unix.so"
echo "account     sufficient    pam_succeed_if.so uid < 500 quiet"
echo "account     required      pam_permit.so"
echo ""
echo "password    required      pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-2 ucredit=-1 ocredit=-1 lcredit=-1 mindiff=3 maxrepeats=2"
echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=12"
echo "password    required      pam_deny.so"
echo ""
echo "session     required      pam_limits.so"
echo "session     required      pam_unix.so"
}

template_system_auth_7(){
echo "#%PAM-1.0"
echo "auth 	required     pam_env.so"
echo "auth 	required     pam_faillock.so preauth audit silent deny=5 unlock_time=900"
echo "auth 	[success=1 default=bad] 	pam_unix.so"
echo "auth 	[default=die] 	pam_faillock.so authfail audit deny=5 unlock_time=900"
echo "auth 	sufficient   pam_faillock.so authsucc audit deny=5 unlock_time=900"
echo "auth      required     pam_shells.so"
echo "auth      required     pam_unix.so likeauth nullok try_first_pass"
echo "auth      required     pam_nologin.so"
echo "auth 	required 	pam_deny.so"
echo ""
echo "#"
echo "account    required     pam_unix.so"
echo "#"
echo "password   requisite     pam_pwquality.so try_first_pass local_users_only authtok_type=Linux retry=3 authtok_type=Linux difok=3 maxrepeats=2 dcredit=-2"
echo "password   sufficient   pam_unix.so remember=12 nullok use_authtok sha512 shadow"
echo "password   required    pam_pwhistory.so use_authtok remember=12"
echo "password   required     pam_deny.so"
echo "#"
echo "session    required     pam_limits.so"
echo "session    required     pam_unix.so"
echo "session    optional     pam_console.so"
echo "-session   optional     pam_systemd.so"
}

template_password_auth_7(){
echo "#%PAM-1.0"
echo "auth      required     pam_env.so"
echo "auth      required     pam_faillock.so preauth audit silent deny=5 unlock_time=900"
echo "auth      [success=1 default=bad]         pam_unix.so"
echo "auth      [default=die]   pam_faillock.so authfail audit deny=5 unlock_time=900"
echo "auth      sufficient   pam_faillock.so authsucc audit deny=5 unlock_time=900"
echo "auth      required     pam_shells.so"
echo "auth      required     pam_unix.so likeauth nullok try_first_pass"
echo "auth      required     pam_nologin.so"
echo "auth      required        pam_deny.so"
echo ""
echo "#"
echo "account    required     pam_unix.so"
echo "#"
echo "password   requisite     pam_pwquality.so try_first_pass local_users_only authtok_type=Linux retry=3 authtok_type=Linux difok=3 maxrepeats=2 dcredit=-2"
echo "password   sufficient   pam_unix.so remember=12 nullok use_authtok sha512 shadow"
echo "password   required    pam_pwhistory.so use_authtok remember=12"
echo "password   required     pam_deny.so"
echo "#"
echo "session    required     pam_limits.so"
echo "session    required     pam_unix.so"
echo "session    optional     pam_console.so"
echo "-session   optional     pam_systemd.so"
}

verif_pass(){
#Verifica punto 7.5.4.0/1/2/3/4
echo "################## Verifica punto 7.5.4.0/1/2/3/4"

if [ "$VER" -lt "7" ]
 then
  ## minlen=14 pero lo baje a 8 
  AUTH_LINE="pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-2 ucredit=-1 ocredit=-1 lcredit=-1 difok=3 maxrepeats=2" 
  VERIF_AUTH=`grep "$AUTH_LINE" $FILE_SYS_AUTH >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "Politica de PASSWORD $FILE_SYS_AUTH $VERIF_AUTH"
  VERIF_TALLY=`grep "pam_tally2" $FILE_SYS_AUTH|grep "deny=5"|grep "onerr=fail" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "Politica de userID lockout $FILE_SYS_AUTH $VERIF_TALLY"
  VERIF_HIST=`grep "remember" $FILE_SYS_AUTH|grep pam_unix.so|grep "remember=12" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "Politica de historia de passwords $FILE_SYS_AUTH $VERIF_HIST"
  ALG_PASS=`grep "pam_unix.so" $FILE_SYS_AUTH | grep sha512 >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "algoritmo de password-hashing $ALG_PASS"
 else
  AUTH_LINE="pam_pwquality.so|retry=3"
  VERIF_AUTH=`grep -E "$AUTH_LINE" $FILE_SYS_AUTH >/dev/null 2>&1 && echo "OK" || echo "ERROR"` 
  echo "Politica de PASSWORD $FILE_SYS_AUTH $VERIF_AUTH"
  AUTH_ENV=`grep "auth" $FILE_SYS_AUTH|grep "pam_faillock.so" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "Politica de Intentos Fallidos $FILE_SYS_AUTH $AUTH_ENV"  
  ALG_PASS=`grep "pam_unix.so" $FILE_SYS_AUTH | grep sha512 >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "algoritmo de password-hashing $ALG_PASS"
  echo $PAM_VALUE|tr "|" "\n"|while read line
   do
    PAM_VARIABLE=`echo $line|cut -d"=" -f1`
    PAM_ATTR=`echo $line|cut -d"=" -f2`
    PAM_SET=`grep "^$PAM_VARIABLE" $FILE_PAM|grep "$PAM_ATTR" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
    echo "$PAM_VARIABLE SETEO $PAM_SET"
  done 
fi 
}


impl_pass(){
#Modifica punto 7.5.4.0/1/2/3/4
echo "################## Modifica punto 7.5.4.0/1/2/3/4"
FILE_SYS_AUTH_LN=`ls -tlra $FILE_SYS_AUTH|awk '{print $11}'`
if [ "$VER" -lt "7" ]
 then
  template_system_auth_5 >$FILE_SYS_AUTH.tasa
  rm -f $FILE_SYS_AUTH
  ln -s $FILE_SYS_AUTH.tasa $FILE_SYS_AUTH
 else
  template_system_auth_7 >$FILE_SYS_AUTH.tasa
  rm -f $FILE_SYS_AUTH
  ln -s $FILE_SYS_AUTH.tasa $FILE_SYS_AUTH
  template_password_auth_7 >$FILE_PASS_AUTH.tasa
  rm -f $FILE_PASS_AUTH
  ln -s $FILE_PASS_AUTH.tasa $FILE_PASS_AUTH
  echo $PAM_VALUE|tr "|" "\n"|while read line
   do
    PAM_VARIABLE=`echo $line|cut -d"=" -f1`
    PAM_ATTR=`echo $line|cut -d"=" -f2`
    PAM_SET=`grep "^$PAM_VARIABLE" $FILE_PAM|grep "$PAM_ATTR" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
    if [ "$PAM_SET" == "ERROR" ] 
     then
      echo "$line" >>$FILE_PAM
      PAM_CHANGE=`cat $FILE_PAM|sed '1{p;s~.*~'$PAM_VARIABLE'='$PAM_ATTR'~;h;d};/^.*'$PAM_VARIABLE'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_PAM.tmp && echo "OK" ||echo "ERROR"`
       
      mv $FILE_PAM.tmp $FILE_PAM
      chmod 644 $FILE_PAM
      echo "$FILE_PAM  $PAM_VARIABLE $PAM_SET == $PAM_CHANGE   $PAM_ATTR"
    fi
   done
fi
}


verif_shadow(){
#Verifica punto 7.5.5.0/1/1.1/1.2/2/3 7.6.2.1
echo "################## Verifica punto 7.5.5.0/1/1.1/1.2/2/3 7.6.2.1"

echo $LOGINDEF_VALUES|tr "|" "\n"|while read VAL
   do
    RVAR=`echo $VAL|awk '{print $1}'`
    RVAL=`echo $VAL|awk '{print $3}'`
    RSTAT=`echo $VAL|awk '{print $2}'`
    VAL_LOGIN=`grep "^$RVAR" $FILE_LOGINDEF|awk '{print $2}'`
    if [ "$RSTAT" == "==" ]
     then
      if [ "$VAL_LOGIN" -eq "$RVAL" ]
       then
        echo "$RVAR SETEADO EN $VAL_LOGIN OK"
       else
        echo "$RVAR SETEADO EN $VAL_LOGIN ERROR"
       fi
     else
       if [ "$VAL_LOGIN" -ge "$RVAL" ]
        then
           echo "$RVAR SETEADO EN $VAL_LOGIN OK PERO SE MODIFICA AL VALOR FIJO"
        else
           echo "$RVAR SETEADO EN $VAL_LOGIN ERROR"
       fi
    fi
done
ROOTUSRID=`grep "^root:" /etc/passwd | cut -f4 -d:`
OTHERROOT=`cat /etc/passwd|cut -d":" -f3|grep "^0"|wc -l`
if [ "$ROOTUSRID" -eq "0" ]
 then
   echo "Root USRID 0 OK"
 else
   echo "Root USRID 0 ERROR"
fi
if [ "$OTHERROOT" -gt "1" ]
 then
  echo "ERROR existen $OTHERROOT con ID 0"
 else
  echo "OK no existen otros usuarios con ID 0"
fi
CHECK_PASS=`/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " NO TIENE PASSWORD "}'`
if [ "$CHECK_PASS" == "" ]
 then
   echo "NO HAY USUARIOS SIN PASSWORD"
fi
}


impl_shadow(){
#Modifica punto 7.5.5.0/1/1.1/1.2/2/3 7.6.2.1
echo "################## Modifica punto 7.5.5.0/1/1.1/1.2/2/3 7.6.2.1"

echo $LOGINDEF_VALUES|tr "|" "\n"|while read VAL
   do
    RVAR=`echo $VAL|awk '{print $1}'`
    RVAL=`echo $VAL|awk '{print $3}'`
    RSTAT=`echo $VAL|awk '{print $2}'`
    VAL_LOGIN=`grep "^$RVAR" $FILE_LOGINDEF|awk '{print $2}'`
    if [ "$RSTAT" == "==" ]
     then
      if [ "$VAL_LOGIN" -eq "$RVAL" -a "$VAL_LOGIN" != "" ]
       then
        echo "$RVAR SETEADO EN $VAL_LOGIN OK"
       else
        LOGIN_CHANGE=`cat $FILE_LOGINDEF|sed '1{p;s~.*~'$RVAR' '$RVAL'~;h;d};/^.*'$RVAR'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_LOGINDEF.tmp && echo "OK" ||echo "ERROR"`
        mv -f $FILE_LOGINDEF.tmp $FILE_LOGINDEF
       fi
     else
       if [ "$VAL_LOGIN" -eq "$RVAL" ]
        then
           echo "$RVAR SETEADO EN $VAL_LOGIN OK"
        else
        LOGIN_CHANGE=`cat $FILE_LOGINDEF|sed '1{p;s~.*~'$RVAR' '$RVAL'~;h;d};/^.*'$RVAR'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_LOGINDEF.tmp && echo "OK" ||echo "ERROR"`
        mv -f $FILE_LOGINDEF.tmp $FILE_LOGINDEF
       fi
    fi
done
}

verif_ras() {
#Verifica punto 7.3.1.10 - '/var/adm/ras/* files are not world readable or writable' 
echo "################## Verifica punto 7.3.1.10 /var/adm/ras/* files are not world readable or writable"
if [ -d "$ADM_RAS" ]
 then
  echo "EXISTE $ADM_RAS"
  find $ADM_RAS -type f -print 
  find $ADM_RAS -type d -print 
 else
  echo "NO EXISTE $ADM_RAS"
fi
}

impl_ras() {
#Modifica punto 7.3.1.10 - '/var/adm/ras/* files are not world readable or writable' 
echo "################## Modifica punto 7.3.1.10 /var/adm/ras/* files are not world readable or writable"

if [ -d "$ADM_RAS" ]
 then
  find $ADM_RAS -type f -print -exec chmod 600 {} \;
  find $ADM_RAS -type d -print -exec chmod 700 {} \;
 else
  mkdir -p $ADM_RAS
  chmod 755 $ADM_RAS
fi
}

verif_user() {
#Verifca 7.5.4.2 Deshabilitar cuentas de sistema que no se utilizan.
echo "################## Verifica 7.5.4.2 Deshabilitar cuentas de sistema que no se utilizan."
for user in `awk -F: '($3 < 100) {print $1 }' /etc/passwd`; do
    if [ $user != 'root' ]; then
      echo "Se modificara usermod -L $user"
      if [ $user != 'sync' ] && [ $user != 'shutdown' ] && [ $user != 'halt' ]; then
        echo "Se modificara usermod -s /sbin/nologin $user"
      fi
    fi
done
}


impl_user() {
#Modifica 7.5.4.2 Deshabilitar cuentas de sistema que no se utilizan.
mkdir /tmp/SOX/tmp
cp -f /etc/passwd /tmp/SOX/tmp/
echo "################## Modifica 7.5.4.2 Deshabilitar cuentas de sistema que no se utilizan."
for user in `awk -F: '($3 < 100) {print $1 }' /etc/passwd`; do
    if [ $user != 'root' ]; then
      usermod -L "$user"
      if [ $user != 'sync' ] && [ $user != 'shutdown' ] && [ $user != 'halt' ]; then
        usermod -s /sbin/nologin "$user"
      fi
    fi
done
}

impl_chpass() {
echo "$ROOT_PASS" | passwd root --stdin
echo "Cambiando password de ROOT....."
}

verif_limits() {
#FILE_LIMITS="/etc/security/limits.conf:*#hard#core#0|/etc/sysctl.conf:fs.suid_dumpable#=#0|EXEC sysctl -w fs.suid_dumpable=0"
echo "######## Verifica 7.1.5.1 Restringir los Core Dumps - LIMITS.CONF##############"
if [ "$VER" == "7" -o "$VER" == "6" ]
 then
   echo "$FILE_LIMITS"|tr "|" "\n"|while read LIMIT
    do
     ACTION=`echo $LIMIT|awk '{print $1}'`
     if [ "$ACTION" == "EXEC" ]
      then
       ARG_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f1`
       VAL_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f2`
       CHECK=`sysctl -a|grep ${ARG_CORE}|grep ${VAL_CORE} >/dev/null && echo "${ARG_CORE} == OK"||echo "${ARG_CORE} == ERROR"`
       echo "${CHECK}"
      else
       FILE_CORE=`echo $LIMIT|cut -d":" -f1`
       VAL_CORE=`echo $LIMIT|cut -d":" -f2|tr "#" " "`
       CHECK=`cat ${FILE_CORE}|tr -s ' ' |grep "${VAL_CORE}" >/dev/null && echo "${FILE_CORE} = ${VAL_CORE} OK" ||echo "${FILE_CORE} = ${VAL_CORE} ERROR"`
       echo "${CHECK}"
     fi
   done
fi
}


impl_limits() {
#FILE_LIMITS="/etc/security/limits.conf:*#hard#core#0|/etc/sysctl.conf:fs.suid_dumpable#=#0|EXEC sysctl -w fs.suid_dumpable=0"
echo "######## Modifica 7.1.5.1 Restringir los Core Dumps - LIMITS.CONF ###########"
if [ "$VER" == "7" -o "$VER" == "6" ]
 then
   echo "$FILE_LIMITS"|tr "|" "\n"|while read LIMIT
    do
     ACTION=`echo $LIMIT|awk '{print $1}'`
     if [ "$ACTION" == "EXEC" ]
      then
       ARG_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f1`
       VAL_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f2`
       CHECK=`sysctl -a 2>/dev/null|grep ${ARG_CORE}|grep ${VAL_CORE} >/dev/null && echo "OK"||echo "ERROR"`
       echo "${CHECK}"
       if [ "$CHECK" == "ERROR" ]
       then
        EXEX=`sysctl -w ${ARG_CORE}=${VAL_CORE} && echo "SYSCTL CHANGE OK" ||echo "SYSCTL CHANGE ERROR"`
       fi
      else
       FILE_CORE=`echo $LIMIT|cut -d":" -f1`
       VAL_CORE=`echo $LIMIT|cut -d":" -f2|tr "#" " "`
       CHECK=`cat ${FILE_CORE}|tr -s ' ' |grep "${VAL_CORE}" >/dev/null && echo "OK" ||echo "ERROR"`
       echo "${CHECK}"
       if [ "$CHECK" == "ERROR" ]
        then
         echo "${VAL_CORE}" >>${FILE_CORE}
        fi
     fi
   done
fi
}

verif_X() {
#Verifica punto 7.2.1.8 X server Instalado
echo "Verificando punto 7.2.1.8 X server Instalado...."
X_EXT=`rpm -qa|grep -i xorg-x11-server >/dev/null && echo "X_NO_INSTALADO" || echo "X_INSTALADO"`
echo "X STATUS = $X_EXT"
}


impl_X() {
#Modifica punto 7.2.1.8 X server Instalado
echo "Modificando punto 7.2.1.8 X server Instalado...."
X_EXT=`rpm -qa|grep -i xorg-x11-server >/dev/null && echo "X_INSTALADO" || echo "X_NO_INSTALADO"`
if [ "$X_EXT" == "X_INSTALADO" ]
 then
 package="xorg-x11"
 pkgs=($(rpm -qa | grep "$package"))

  for i in "${pkgs[@]}"
   do
    echo "rpm -e --nodeps $i"
    rpm -e --nodeps $i
  done
fi
verif_X 
}


impl_register() {
perl <<'__BEGIN__'
use strict;
use IO::Socket::INET;
use Sys::Hostname;
my $sock = new IO::Socket::INET(PeerAddr => '10.204.167.9', PeerPort => 47100,Proto => 'udp',Timeout => 1) or die('Error opening socket.'); 
my $host = qx(uname -n|cut -d. -f1); 
my $date = localtime();
my $type = 'IMPL=';
my $data = "$type $date: $host"; 
print $sock $data;
__BEGIN__
}

verif_register() {
perl <<'__BEGIN__'
use strict;
use IO::Socket::INET;
use Sys::Hostname;
my $sock = new IO::Socket::INET(PeerAddr => '10.204.167.9', PeerPort => 47100,Proto => 'udp',Timeout => 1) or die('Error opening socket.'); 
my $host = qx(uname -n|cut -d. -f1); 
my $date = localtime();
my $type = 'TEST=';
my $data = "$type $date: $host"; 
print $sock $data;
__BEGIN__
}

verif_segdatos(){
#Verfica segdatos
echo "Verifica que exista usuario segdatos..."
USERV=`grep segdatos /etc/passwd 2>/dev/null`
  if [ "$USERV" == "" ]
   then
     echo "ERROR: usuario segdatos NO EXISTE"
    else
     echo "OK: usuario segdatos EXISTE"
   fi
}

creauser(){
groupadd segabm
useradd -m -s /usr/bin/bash segdatos
}

cambiapass(){
KEY="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAIEA0xJyfIi1NLqm5gk460n7KBDCmrj+zW+kBuBBxfPag4gx0n5IGyfwwb7QP4OpqoC4/6fh7WKj4lV1coLy4UkiPBbHQAC8UyNr8XbrblCTy+wSUH3CISWBCdl20x1qFJ4Rc48pCmH1y6MytaKTKJ8rKLZNEGPGjmgr5JMYDyBT3Oc= segdatos@apsatt3z01"
echo 'segdatos:U53s0gbo'| chpasswd;faillock --user segdatos --reset;chage -E -1 segdatos;chage -M -1 segdatos
mkdir /home/segdatos/.ssh;chmod 700 /home/segdatos/.ssh; echo '$KEY' >> /home/segdatos/.ssh/authorized_keys;chown -R segdatos:segabm /home/segdatos/.ssh;chmod 600 /home/segdatos/.ssh/authorized_keys
}


impl_segdatos(){
#implementa segdatos
echo "Implementa que exista usuario segdatos..."
USERV=`grep segdatos /etc/passwd 2>/dev/null`
  if [ "$USERV" == "" ]
   then
    creauser
    cambiapass
    else
     echo "OK: usuario segdatos EXISTE"
    #cambiapass
   fi
}

impl_chage() {
for USER in cconfsoc gestkeyh segdatos usaddm tfaipat1 beasvc oracle ctmagent doxadm doxdba doxesb doxinfra doxmig doxods doxops gesinc ibmbas ibmbkp ibmdb2 ibmdba ibmimple ibmmid ibmoper ibmsop ibmstg ibmunx ibmweb segabm segunix tgtarq tgtn2be tgtn2fe
do
 chage -M -1 ${USER}
 chage -E -1 ${USER}
done
}

#impl_rpc(){
#systemctl disable rpcbind.service rpcbind.socket
#systemctl stop rpcbind.service rpcbind.socket
#}


verif() {
echo "Verificando...."
ver_dis_fs_prot
verif_fs
verif_vg_space
verif_dir_perms
verif_rhn
verif_gpgcheck
verif_grub
verif_sysctl
verif_banner
verif_inetd
verif_ntp
verif_X
verif_services
verif_mail
verif_net
verif_wireless
verif_audit
verif_audit_rules
verif_rsyslog
verif_logrotate
verif_history
verif_cron
verif_ssh
verif_pass
verif_shadow
verif_limits
#verif_ras
verif_limits
verif_user
verif_X
verif_spkey
verif_register
verif_segdatos
verif_ibmunx_user
}

implementa() {
echo "Voy a implementar"
backup_action backup
impl_dis_fs_prot
ver_dis_fs_prot
impl_fs
verif_fs
#change_dir_perms
#verif_dir_perms
verif_rhn
impl_gpgcheck
verif_gpgcheck
impl_grub
verif_grub
impl_sysctl
verif_sysctl
impl_banner
verif_banner
impl_inetd
verif_inetd
impl_ntp
verif_ntp
impl_X
verif_X
impl_services
verif_services
impl_net
verif_net
impl_wireless
verif_wireless
impl_audit
verif_audit
impl_audit_rules
verif_audit_rules
impl_rsyslog
verif_rsyslog
impl_history
verif_history
impl_logrotate
verif_logrotate
impl_cron
verif_cron
impl_ssh
verif_ssh
impl_pass
verif_pass
impl_shadow
verif_shadow
impl_ras
verif_ras
verif_user
impl_user
impl_limits
#impl_chpass
impl_X
impl_spkey
impl_register
impl_segdatos
verif_ibmunx_user
impl_ibmunx
impl_chage
impl_rpc
}

test_module() {
echo "testea algun modulo"
MODULO=$1
echo "$MODULO"
$MODULO
}


lista_modulos() {
echo "Modulos disponibles para test"
cat "$0" |grep "()"|grep verif_|cut -d"(" -f1|grep -v "cat"
}

help() {
 VERSIONS="SOX script V 2.5.2"
 echo "$VERSIONS"
 echo "$0 [ -v|-i|-restore|-h]"
 echo " -v : verifica antes de implementar"
 echo " -i : implementa y hace backup"
 echo " -restore : recupera de un backup"
 echo " -test : testea un modulo"
 echo " -list : lista modulos"
 echo " -h : este help"
}


lnx_ver
common_param

case $OPTION in
    -v ) verif ;;
    -restore ) backup_action restore;;
    -i ) implementa ;;
    -test ) test_module $MODULE;;
    -list ) lista_modulos;;
    -h | * ) help ;;
esac


