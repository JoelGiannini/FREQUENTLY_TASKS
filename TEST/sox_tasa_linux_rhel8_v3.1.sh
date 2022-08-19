#!/bin/bash
#13/07/2020 certificado en RHEL 8 con Seguridad.

OPTION=$1
MODULE=$2
SCRIPTVER="3.1"

serror(){
RUN="$1"
DESCRIPTION="$2"
if [ "$RUN" == "0" ]
then
 echo "**** $DESCRIPTION"
 RUN="0"
fi
if [ "$ERROR" != "" ]
 then
  printf "\t ERROR: $STATUS\n"
 else
  printf "\tCHECK_STATUS: $STATUS\n"
fi
}

lnx_ver() {
UNAME=`uname -s`
MACHINE_NAME=`uname -n`
MACHINE_TYPE=`lscpu|grep -iE 'Vendor ID|Model name:|Virtualization:|Hypervisor vendor:'|tr "\n" " "` 
MACHINE_CREATION=`fs=$(df / | tail -1 | cut -f1 -d' ') && tune2fs -l $fs 2>/dev/null| grep created|cut -d":" -f2,3,4`
DESCRIPTION="Verificando Sistema Operativo Linux"
if [ "$UNAME" == "Linux" ]
then
WHERE=`whereis lsb_release >/dev/null 2>&1`
if [ "$WHERE" != "" ]
 then
  EXEC=`$WHERE -dr`
  DISTRIB=`echo $EXEC|grep "Description:"|awk '{print substr($0,index($0,$2))}'`
  VER=`echo $EXEC|grep "Release:"|cut -d"." -f1`
 else
   if [ -f /etc/os-release ]
    then
    VER=`cat /etc/os-release|grep VERSION_ID|cut -d"=" -f2|cut -d"." -f1|tr -d "\""`
    DISTRIB=`cat /etc/os-release|grep PRETTY_NAME|cut -d"=" -f2|awk '{print $1}'|tr -d "\""` 
    else
    if [ -f /usr/bin/hostnamectl ]
     then
      VER=`/usr/bin/hostnamectl|grep "CPE OS Name"|cut -d":" -f6`
      DISTRIB=`/usr/bin/hostnamectl|grep "Operating System"|cut -d":" -f2`
     else
     if [ -f /etc/redhat-release ]
      then
       VER=`cat /etc/redhat-release|awk '{print $3}'|cut -d"." -f1`
       DISTRIB=`cat /etc/redhat-release|awk '{print $1}'`
      else 
      VER="NO_ID_AVAIL"
      DISTRIB="NO_DISTRIB_AVAIL"
    fi
    fi
   fi
fi

if [ "$DISTRIB" == "Red" ]
 then
  DISTRIB="RHEL"
fi
STATUS="\tDITRIBUTION=  $VER  $DISTRIB\n\tMACHINE_NAME=  ${MACHINE_NAME}\n\tMACHINE_TYPE=${MACHINE_TYPE}\n\tMACHINE_CREATION=${MACHINE_CREATION}\n"
serror

else
 STATUS="Este script solo se puede correr en Linux: ${UNAME}\n"
 serror
fi
}


common_param() {
   HOSTNAME=`hostname`
   if [ "$DISTRIB" != "SUSE" ]
   then
     DEFAULT_GW=`netstat -rn|grep -iE "default|^0.0.0.0"|awk '{print $2}'`
   else
     DEFAULT_GW=`ip route|grep default|awk '{print $3}'`
   fi
   DATE=`date +%Y%d%m%H%M`
   GRUB2_SET="ipv6.disable=1|audit=1|audit_backlog_limit=8192"
   FILE_FS=/etc/modprobe.d/CIS.conf
   FILE_SUDO=/etc/sudoers
   FILE_PASSWD=/etc/passwd
   FS_TYPE="cramfs freevxfs jffs2 hfs hfsplus squashfs udf vfat fat usb-storage"
   FS_TYPE_SAP="cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage"
   FILE_PERMS=/tmp/perms_dir.txt
   FILE_YUM=/etc/yum.conf 
   FILE_GRUB2=/boot/grub2/grub.cfg
   FILE_GRUB=/boot/grub/grub.conf
   FILE_SYSCTL=/etc/sysctl.conf
   FILE_MOTD=/etc/motd
   FILE_ISSUE=/etc/issue
   FILE_ISSUE_NET=/etc/issue.net
   FILE_INETD=/etc/xinetd.d
   FILE_NTP="/etc/ntp.conf /etc/chrony.conf"
   FILE_NTP_SYS=/etc/sysconfig/ntpd
   FILE_NTP_SERV=/usr/lib/systemd/system/ntpd.service
   FILE_AVAHI=/etc/default/avahi-daemon
   FILE_SENDMAIL=/etc/mail/sendmail.cf
   FILE_POSTFIX=/etc/postfix/main.cf
   OPTS_POSTFILS="inet_interfaces = loopback-only"
   FILE_MAIL7=/etc/postfix/main.cf
   FILE_AUDIT=/etc/audit/auditd.conf
   FILE_AUDIT_RULES=/etc/audit/audit.rules
   FILE_RSYSLOGD=/etc/rsyslog.conf
   FILE_SUDOERS="/etc/sudoers"
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
   CORE_ARG="Storage=none|ProcessSizeMax=0"
   FILE_CORE="/etc/systemd/coredump.conf"
   FILE_PWQUALITY=/etc/security/pwquality.conf 
   FILE_LIMITS="/etc/security/limits.conf:*#hard#core#0|/etc/sysctl.conf:fs.suid_dumpable#=#0|EXEC sysctl -w fs.suid_dumpable=0"
   NTP_CONF="restrict -4 default kod nomodify notrap nopeer noquery|restrict -6 default kod nomodify notrap nopeer noquery"
   LOGINDEF_VALUES="PASS_MAX_DAYS == 30|PASS_MIN_DAYS == 0|UID_MIN == 1000|UID_MAX == 60000|PASS_WARN_AGE == 5"
   #PAM_VALUE_8="minclass=6|minlen=8|dcredit=-2|lcredit=-1|ocredit=-1|ucredit=-1|difok=3|maxrepeats=2|mindiff=3"
   PAM_VALUE_8="minclass=6|minlen=8|dcredit=-2|lcredit=-1|ocredit=-1|ucredit=-1|difok=3|mindiff=3"
   FILE_AUTH_SYSTEM_AUTH="/usr/share/authselect/default/sssd/system-auth"
   FILE_AUTH_PASSWORD_AUTH="/usr/share/authselect/default/sssd/password-auth"
   FILE_AUTH_SU_AUTH="/etc/pam.d/su"
   PAM_VALUE="minlen=8|dcredit=-2|lcredit=-1|ocredit=-1|ucredit=-1|difok=3"
   SSH_PARAM="Protocol 2|LogLevel INFO|MaxAuthTries 3|IgnoreRhosts yes|HostbasedAuthentication no|PermitRootLogin no|PermitEmptyPasswords no|PermitUserEnvironment no|ClientAliveInterval 1800|ClientAliveCountMax 0|Banner /etc/issue.net|X11Forwarding no|Match address 10.204.167.185,10.204.164.159,10.206.19.47,10.166.13.238,10.166.13.254,10.166.31.102|LoginGraceTime 60|UsePAM yes|AllowTcpForwarding no|maxstartups 10:30:60|MaxSessions 4|Ciphers aes128-ctr,aes192-ctr,aes256-ctr|MACs hmac-sha1,umac-64@openssh.com|PubkeyAcceptedKeyTypes=+ssh-dss"
   SSH_PARAM_EXEP="ClientAliveInterval 1800"
   GENERAL_PERMS="/etc/crontab chown_root:root chmod_600|/etc/cron.hourly chown_root:root chmod_700_d|/etc/cron.daily chown_root:root chmod_700_d|/etc/cron.weekly chown_root:root chmod_700_d|/etc/cron.monthly chown_root:root chmod_700_d|/etc/cron.d chown_root:root chmod_700_d|/etc/ssh/sshd_config chown_root:root chmod_600|/etc/passwd chown_root:root chmod_644|/etc/shadow chown_root:root chmod_000|/etc/group chown_root:root chmod_644|/etc/gshadow chown_root:root chmod_000|/etc/cron.allow chown_root:root chmod_600|/etc/at.allow chown_root:root chmod_600|/etc/passwd- root:root chmod_600|/etc/group- root:root chmod_600|/etc/shadow- root:root chmod_600|/etc/group- root:root chmod_600|/etc/gshadow- root:root chmod_600|/etc/profile root:root chmod_644|/etc/bashrc root:root chmod_644|/var/log root:root chmod_755|/var/log/hist root:root chmod_755"
   GENERAL_ABM="/etc/cron.allow touch|/etc/at.allow touch|/etc/cron.deny rm|/etc/at.deny rm"
   RSYSLOGD_ATTR="auth.debug  /var/log/authlog chown_root:root|*.info;auth.none   /var/log/syslog chmod_600|*.warn;auth.none    /var/log/messages chmod_640|*.info;mail.none;authpriv.none;cron.none;auth.none  /var/log/messages chmod_640"
   FILE_JOURNAL="/etc/systemd/journald.conf"
   JOURNAL_ATTR="ForwardToSyslog=yes|Compress=yes|Storage=persistent"
   ADM_RAS="/var/adm/ras"
   SIEM_SERVER="*.* @10.167.19.51"
   TMP_FS_7_FILE=/etc/systemd/system/local-fs.target.wants/tmp.mount
   SERVER_NTP="serve svaix srvrh srvsun:soteclock soteclock2 soteclock3|ct3racp:10.167.144.1|#%:$DEFAULT_GW"
   SERVICES_DISABLE="avahi-daemon cups dhcpd slapd nfs nfsloc rpcgssd rpcidmapd portmap  rpcbind.socket rpcbind.target rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd openldap-servers dhcp net-snmp rsh-server talk-server telnet-server tftp"
   SERVICES_REFUSED="httpd nfs smb dovecot squid vsftpd nfsloc rpcgssd rpcidmapd portmap"
   SERVICES_ENABLE="auditd rsyslog crond"
   SERVICE_REMOVE="dhcp openldap-servers bind httpd dovecot samba squid net-snmp ypserv rsh-server talk-server telnet-server tftp"
   PACK_NTP="ntp chrony"
   INETD_SERVICES="chargen-dgram chargen-stream daytime-dgram daytime-stream discard-dgram discard-stream echo-dgram echo-stream time-dgram time-stream tftp"
   PROTOCOL_DISABLE="ipv6 dccp sctp rds tipc"
   BACKUP_LOC=/var/sox_tasa/backup
   BACKUP_TARGET=$BACKUP_LOC"/backup_sox_tasa_"$DATE".tar"
   FSTAB="/etc/fstab"
   FILESYS="/tmp /home /dev/shm cdrom /var/tmp"
   AUDITFS=/var/log/audit
   AUDITFSSIZE="10G"
   AUDIT_IDENTITY="/etc/group /etc/passwd /etc/shadow /etc/gshadow /etc/security/opasswd /etc/sudoers"
   AUDIT_AUDITING="/etc/audit/audit.rules /etc/audit/auditd.conf /etc/libaudit.conf /etc/sysconfig/auditd /etc/login.defs /etc/security/limits.conf /etc/ssh/sshd_config /etc/rsyslog.conf /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/ /etc/cron.d/ /etc/crontab"
   NET_DISABLE="net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv6.conf.all.forwarding net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra"
   NET_ENABLE="net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.tcp_syncookies net.icmp_echo_ignore_broadcasts net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter"
   BACKUP_FILES="/etc /boot"
   FILES_AUDIT_8="VAR_SCOPE:/etc/audit/rules.d/01-scope.rules VAR_AUDIT:/etc/audit/rules.d/00-audit.rules VAR_LOGINS:/etc/audit/rules.d/02-logins.rules VAR_TIME:/etc/audit/rules.d/03-time-change.rules VAR_MAC:/etc/audit/rules.d/04-MAC-policy.rules VAR_LOCALE:/etc/audit/rules.d/05-system-locale.rules VAR_PERM:/etc/audit/rules.d/06-perm_mod.rules VAR_ACCESS:/etc/audit/rules.d/07-access.rules VAR_IDENTITY:/etc/audit/rules.d/08-identity.rules VAR_MOUNTS:/etc/audit/rules.d/09-mounts.rules VAR_DELETE:/etc/audit/rules.d/10-delete.rules VAR_MODULES:/etc/audit/rules.d/11-modules.rules VAR_FINAL:/etc/audit/rules.d/99-finalize.rules"
   VAR_SCOPE="-w /etc/sudoers -p wa -k scope| -w /etc/sudoers.d/ -p wa -k scope|-w /var/log/sudo.log -p wa -k actions"
   VAR_AUDIT="-w /var/log/faillog -p wa -k logins| -w /var/log/lastlog -p wa -k logins"
   VAR_LOGINS="-w /var/run/utmp -p wa -k session| -w /var/log/wtmp -p wa -k logins| -w /var/log/btmp -p wa -k logins"
   #VAR_TIME="-a always,exit -F arch=b64 -S adjtimex -S time -k timechange| -a always,exit -F arch=b32 -S adjtimex -S time -S stime -k timechange| -a always,exit -F arch=b64 -S clock_settime -k timechange| -a always,exit -F arch=b32 -S clock_settime -k timechange| -w /etc/localtime -p wa -k timechange"
   VAR_TIME="-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change| -a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change|-a always,exit -F arch=b64 -S clock_settime -k time-change| -a always,exit -F arch=b32 -S clock_settime -k time-change| -w /etc/localtime -p wa -k time-change"
   VAR_MAC=" -w /etc/selinux/ -p wa -k MAC-policy| -w /usr/share/selinux/ -p wa -k MAC-policy|-w /etc/apparmor/ -p wa -k MAC-policy|-w /etc/apparmor.d/ -p wa -k MAC-policy"
   VAR_LOCALE=" -a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale| -a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale| -w /etc/issue -p wa -k system-locale|-w /etc/issue.net -p wa -k system-locale| -w /etc/hosts -p wa -k system-locale| -w /etc/sysconfig/network -p wa -k system-locale"
   VAR_PERM="-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod|-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod|-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod|-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod|-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod|-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
   VAR_ACCESS="-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access|-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access|-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access|-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
   VAR_IDENTITY="-w /etc/group -p wa -k identity|-w /etc/passwd -p wa -k identity|-w /etc/gshadow -p wa -k identity|-w /etc/shadow -p wa -k identity|-w /etc/security/opasswd -p wa -k identity"
   VAR_MOUNTS="-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts|-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts"
   VAR_DELETE="-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete|-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
   VAR_MODULES="-w /sbin/insmod -px -k modules|-w /sbin/rmmod -px -k modules|-w /sbin/modprobe -px -k modules|-a always,exit -F arch=b64 -S init_module -S delete_module -k modules|-a always,exit -F arch=b32 -S init_module -S delete_module -k modules"
   VAR_FINAL="-e 2"
   FILESYS_SUSE_OPTS="/tmp#rw,nosuid,nodev,noexec,relatime|/var#rw,relatime,data=ordered|/var/tmp#rw,nosuid,nodev,noexec,relatime|/var/log#rw,relatime,data=ordered|/var/log/audit#rw,relatime,data=ordered|/home#rw,nodev,relatime,data=ordered|/dev/shm#rw,nosuid,nodev,noexec,relatime"
   FILESYS_CENTOS_OPTS="/tmp#rw,nodev,nosuid,noexec|/var#rw,relatime|/var/tmp#rw,nodev,nosuid,noexec|/home#rw,nodev|/dev/shm#nodev,nosuid,noexec"

}

spkey_common() {
KPUB="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAtSiP8SYFqPQ7KNHuK460LHJ3KnyofUJP3fWE4dYKWYVEGL//rS50ZyLoSvTEWVTZNVvg9kVXeiV0GHvPBnDlijB8zXZPuLBa49Rg+7SYC835vU7kLFjqoaHG+J3yAEzkHrD7rwQDxlDT2bIL1FV3uBN7fdCaACCZrFR/o3yXYr5qxE9BpJnGykdyPrB/NOsSLMMgCnFvvX/fF/H1rLAo/p7lZNJ9dOT2N8lXvcXHaPuei8m29fVHPKM3C3lo2U9jL9i89c24j19UjpdZc+0UXja+81W9Sk/bqbBVKgCuVnVbKLZX7Ye+nCrndia6KAVWv2Yx0CuTPGteh7xUWE6Raw== cconfsoc@Gstp"
SUSER="cconfsoc"
FILE_AUTH=".ssh/authorized_keys"
SUSER_HOME=`grep ${SUSER} /etc/passwd|cut -d":" -f6`
}

spkey_ibmunx() {
KIBMUNX="ssh-dss AAAAB3NzaC1kc3MAAACBANtKI2IlMM63qshnj1E5Qubvke/yn/qkV3fkUecDCLDGuA09R5YxKrY833DjykbNna0FRDpc0WhA0GBbPRgCvK55L44TM7nUKgfG1m+M14ps6KEYnaHf8U8LR0CGuRA5rf3HScqHpvl89CYBivedWOFEgD8XCXtEQ5h9So/WgKdPAAAAFQDXEHid2tjCEpAofya/0ipEzpf8DwAAAIBKzwBltdlo95b5hqN6aGZVKYZqfMwKQeoqTBzqdz+CJLU/dPobDMBplNXLBSY0sU5qLjvQiLFZdg4rJTIbQBfp+G+jBGaAQwuFc47OAv4RPMKc79enPHeE8rR0iO5foD12EqKEpZlT1mc8Rz0NzWSpcQOi9KQehok29EaQ/BfWEgAAAIB/4Vqc2IZzppuLurM0NG3vpwv22LRAi9aiuObtZuu24iRtZ8RmVBqij7g95SC1RfcOucAMfrHsLq0xOgwt5rMwl274jG3hwre0KISV9fpyVvV8ECPh6o2rIkUHdvGv4Hy6bAEWXKUAI27cW5UX/RFXITlJxga4uIB840XYfEyGIw== root@bastionamdocs"
SUSER="ibmunx"
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
   chmod 750 ${SUSER_HOME}/.ssh
fi
   chmod 640 "${SUSER_HOME}/${FILE_AUTH}"
   chown ${SUSER}:${SUSER} "${SUSER_HOME}/${FILE_AUTH}"
   chmod 750 ${SUSER_HOME}/.ssh
}


backup_action() {
ACTION=$1
mkdir -p "$BACKUP_LOC"
STATUS=""
ERROR=""
 if [ "$ACTION" == "backup" ]
  then
   tar cvzf $BACKUP_TARGET $BACKUP_FILES 2>/dev/null && echo "BACKUP OK" || echo "BACKUP FAIL"
  else
    if [ "$ACTION" == "restore" ]
      then
       DESCRIPTION="Restoreo de $BACKUP_TARGET"
       RUN="1"
       ls -ltr $BACKUP_LOC
       echo "Ingrese un file a restorear:"
       read A
       (cd / ; tar xvzf $BACKUP_LOC/$A --exclude=passwd --exclude=shadow --exclude=group ) 2>/dev/null && STATUS="Restore OK" || ERROR="Restore FAIL"
       serror
      else
       echo "Debe ingresar una opcion: backup o restore"
    fi
 fi
}

ver_dis_fs_prot() {
   DESCRIPTION="1.1.1.1/1.1.1.2/1.1.1.3/1.1.1.4/1.1.1.5/1.1.1.6/1.1.1.7/1.1.1.8 disable cramfs/freevxfs/jffs2/hfs/hfsplus/squashfs/udf/vfat  (Redhat, SUSE, CentOS, Ubuntu, Debian)" 
   echo "**** $DESCRIPTION"
   for F in $FS_TYPE $PROTOCOL_DISABLE
    do
     STATUS=`modprobe -n -v $F >/dev/null 2>&1 && echo "$F ESTA_CARGADO" || echo "$F NO_ESTA_CARGADO"`
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

impl_dis_fs() {
 DESCRIPTION="1.1.1.1/1.1.1.2/1.1.1.3/1.1.1.4/1.1.1.5/1.1.1.6/1.1.1.7/1.1.1.8 disable cramfs/freevxfs/jffs2/hfs/hfsplus/squashfs/udf/vfat  (Redhat, SUSE, CentOS, Ubuntu, Debian)"
 if [ -z "$SAP" -a "$SAP" == "1" ] 
  then
    FS_TYPE="$FS_TYPE_SAP" 
 fi
  
 echo "**** $DESCRIPTION"
 for F in $FS_TYPE $PROTOCOL_DISABLE
  do
  if [ "$DISTRIB" != "Ubuntu" ]
  then
   if [ "$DISTRIB" == "RHEL" -a "$VER" -ge "8" ]
    then
     if [ "$F" == "ipv6" ]
      then
      echo "GRUB_CMDLINE_LINUX=\"ipv6.disable=1\"" >/etc/default/grub
     fi
     MOUNTF=`cat $FSTAB|grep -v "#"|grep $F >/dev/null 2>&1 && echo "MONTADO" || echo "OK"`
    if [ "$MOUNTF" == "OK" ]
    then
     echo "install ${F} /bin/true" > /etc/modprobe.d/${F}.conf
     rmmod ${F}
    fi   
  else
   echo "install ${F} /bin/true" >>$FILE_FS
   rmmod ${F}
  fi
 else
 echo "install ${F} /bin/true" > /etc/modprobe.d/blacklist.conf
 fi
 echo "Configurando ${F} disable en $DISTRIB $VER"
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
DESCRIPTION="Verificando  puntos 1.1.2/3/4/5/6/7/8/9/10/14/15/16/17/18/19/20"
echo "**** $DESCRIPTION"

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
DESCRIPTION="Modificando puntos 1.1.2/3/4/5/6/7/8/9/10/14/15/16/17/18/19/20"
echo "**** $DESCRIPTION"

for FS in $FILESYS
  do
   search_fs_infile
   echo "FS= $FS VERIF= $VERIF"
   if [ "$VER" -ge "7" -a "$FS" == "/tmp" -a "$VERIF" != "OK" -a -f "$TMP_FS_7_FILE" ]
    then
     CHFS=`sed '/^Options/ s/$/,nodev,nosuid,noexec,strictatime/' $TMP_FS_7_FILE >$TMP_FS_7_FILE.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
     if [ "$CHFS" == "CH_OK" ]
      then
       mv -f $TMP_FS_7_FILE.tmp $TMP_FS_7_FILE
       mount -o remount ${FS}
      else
       echo "$FS NOT IN $TMP_FS_7_FILE"
     fi
   else

      if [ "$FS" == "/dev/shm" -a "$VERIF" != "OK" ]
       then
         SHM_EXT=`grep "/dev/shm" $FSTAB 2>/dev/null 2>&1 && echo "OK" || echo "NO"`
         if [ "${SHM_EXT}" == "NO" -a "$VER" -ge "7" ]
          then
           SHM_EXEC=`echo "tmpfs /dev/shm tmpfs noexec,nodev,nosuid 0 0" >>$FSTAB && echo "OK" ||echo "ERROR"`
           echo "ENTREEE $SHM_EXEC"
           if [ "$SHM_EXEC" != "ERROR" ]
            then
            mount -o remount,noexec,nodev,nosuid /dev/shm
           fi
         else  
        CHFS=`awk -v v=$FS ' $2==v { $4=$4",nodev,nosuid,noexec" ;} 1' <$FSTAB >${FSTAB}.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
       fi
      fi

      if [ "$FS" == "/home" -a "$VERIF" != "OK" -a "$FS" != "/dev/shm" ]
        then
           CHFS=`awk -v v=$FS ' $2==v { $4=$4",nodev,relatime,data=ordered" ;} 1' <$FSTAB >${FSTAB}.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
          if [ "$CHFS" == "CH_OK" ]
           then
            mv -f ${FSTAB}.tmp $FSTAB
            mount -o remount ${FS}
           else
            echo "$FS ERROR NO ESTA EN $FSTAB"
          fi
        else
         if [ "$VERIF" != "OK" ]
          then
           if [ "$FS" == "/var" ]
            then
             CHFS=`awk -v v=$FS ' $2==v { $4="defaults,relatime,data=ordered" ;} 1' <$FSTAB >$FSTAB.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
            else
            if [ "$FS" != "/dev/shm" ]
            then
             CHFS=`awk -v v=$FS ' $2==v { $4=$4",nodev,nosuid,noexec,relatime,data=ordered" ;} 1' <$FSTAB >$FSTAB.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
            fi
           fi
          if [ "$CHFS" == "CH_OK" ]
           then
            mv -f ${FSTAB}.tmp $FSTAB
            mount -o remount ${FS}
           else
            echo "$FS ERROR in $FSTAB"
          fi
         fi
      fi
   fi
mount -o remount ${FS}
if [ "${FS}" == "/tmp" -a "$DISTRIB" == "RHEL" ]
 then
  systemctl unmask tmp.mount
  systemctl enable tmp.mount
fi
STATUS="$FS $CHFS"
done
}

verif_dir_perms() {
DESCRIPTION="Verificando punto 1.1.21"

echo "**** $DESCRIPTION"
if [ -z "$SAP" -a "$SAP" == "1" ]
 then
   echo "NO aplica a pedido de SAP"
  else
   #df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
   COUNT=`df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null|wc -l`
fi
if [ $COUNT -eq 0 ]
 then
  echo "No hay Directorios que modificar"
fi
}


change_dir_perms() {
DESCRIPTION="Modificando punto 1.1.21"
echo "**** $DESCRIPTION"

verif_dir_perms >$FILE_PERMS

echo "$COUNT"
if [ "$COUNT" -ne "0" ]
 then
   IMPL_CHMOD=`df --local -P | awk '{if (NR!=1) print $6}'| xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null|xargs chmod a+t && echo "CHMOD OK" || echo "CHMOD FAILED"`
   echo "$IMPL_CHMOD"
else
   echo "No hay Directorios que modificar"
fi
}

verif_automount() {
DESCRIPTION="Verificando 1.1.22  Deshabilitar montaje Automatico"
echo "**** $DESCRIPTION"
STATUS=`systemctl is-enabled autofs`
echo "$STATUS"
}

impl_automount() {
DESCRIPTION="Modificando 1.1.22  Deshabilitar montaje Automatico"
echo "**** $DESCRIPTION"
STATUS=`systemctl --now disable autofs`
echo "$STATUS"
}

verif_rhn() {
DESCRIPTION="Verificando punto 1.2.1"
echo "**** $DESCRIPTION"
COUNT=`ps agx 2>/dev/null |grep rhnsd|grep -v grep|wc -l`
if [ "$COUNT" -eq "0" ]
 then
   STATUS="RHN no configurada consultar administrador"
 else
   STATUS="RHN esta OK"
fi
}

verif_gpgcheck() {
DESCRIPTION="Verificando punto 1.2.4"
echo "**** $DESCRIPTION"
VERIF_GPGCHECK=`grep "gpgcheck=1" $FILE_YUM >/dev/null 2>&1 && echo "GPGCHECK set OK" || echo "GPGCHECK set disable"`
echo "$VERIF_GPGCHEC"
VERIF_CLAVEGPG=`rpm -q --queryformat "%{SUMMARY}\n" gpg-pubkey|grep -v "is not installed"|wc -l`
if [ "$VERIF_CLAVEGPG" -eq "0" ]
 then
  STATUS="GPG-PUBKEY NO Instalada"
 else
  STATUS="GPG-PUBKEY OK"
fi
echo "$STATUS"
}

impl_gpgcheck() {
DESCRIPTION="Modificando punto 1.1.23/24"
echo "**** $DESCRIPTION"
IMPL_GPGCHECK=`cat $FILE_YUM|sed -e 's/gpgcheck=0/gpgcheck=1/g' >${FILE_YUM}.tmp 2>&1 && echo "GPGCHECK set OK" || echo "GPGCHECK set disable"`
if [ "$IMPL_GPGCHECK" == "GPGCHECK set OK" ]
 then
   mv -f ${FILE_YUM}.tmp $FILE_YUM
   STATUS="$IMPL_GPGCHECK"
 else
   STATUS="Enable GPGCHECK FAILED"
   echo $STATUS
fi
echo "$STATUS"
}


impl_gpgcheck_suse(){
	echo "gpgcheck=1" >>/etc/zypp/zypp.conf
}

verif_sudo() {
DESCRIPTION="Verificando 1.3.1   Asegúrese de que sudo esté instalado"
echo "**** $DESCRIPTION"
STATUS=`rpm -qa|grep -i sudo`
RUN=1
if [ "$STATUS" == "" ]
 then
  STATUS="SUDO NO ESTA INSTALADO"
fi
echo "$STATUS"
}

impl_sudo() {
DESCRIPTION="Modificando 1.3.1   Asegúrese de que sudo esté instalado"
echo "**** $DESCRIPTION"
STATUS=`rpm -qa|grep -i sudo`
if [ "$STATUS" == "" ]
 then
  STATUS="SUDO NO ESTA INSTALADO"
fi
echo "$STATUS"
}

verif_sudo_opts() {
DESCRIPTION="Verificando 1.3.2   Asegúrese de que los comandos sudo usen pty/1.3.3   Asegúrese de que exista el archivo de registro sudo"
echo "**** $DESCRIPTION"
SUDO_PTY=`grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty' $FILE_SUDOERS && echo "pty esta seteado" || echo "pty no esta seteado"`
SUDO_LOG=`grep -Ei '^\s*Defaults\s+([^#]+,\s*)?logfile=' $FILE_SUDOERS && echo "log esta seteado" || echo "log no esta seteado"`
echo "$SUDO_PTY"
echo "$SUDO_LOG"
}

impl_sudo_opts() {
DESCRIPTION="Modificando 1.3.2   Asegúrese de que los comandos sudo usen pty/1.3.3   Asegúrese de que exista el archivo de registro sudo"
echo "**** $DESCRIPTION"
SUDO_PTY=`grep -Ei '^\s*Defaults\s+(\[^#]+,\s*)?use_pty' $FILE_SUDOERS && echo "OK" || echo "NO"`
SUDO_LOG=`grep -Ei '^\s*Defaults\s+([^#]+,\s*)?logfile=' $FILE_SUDOERS && echo "OK" || echo "NO"`

if [ "$SUDO_PTY" == "NO" ]
 then
   tac $FILE_SUDOERS | awk '!p && /Defaults/{print "Defaults use_pty"; p=1} 1'|tac >${FILE_SUDOERS}.tmp
   mv ${FILE_SUDOERS}.tmp $FILE_SUDOERS
   chmod 440 $FILE_SUDOERS
   chown root:root $FILE_SUDOERS
fi

if [ "$SUDO_LOG" == "NO" ]
 then
  tac ${FILE_SUDOERS} | awk '!p && /Defaults/{print "Defaults logfile=/var/log/sudo.log"; p=1} 1'|tac >${FILE_SUDOERS}.tmp
  mv ${FILE_SUDOERS}.tmp $FILE_SUDOERS
  chmod 440 $FILE_SUDOERS
  chown root:root $FILE_SUDOERS
fi
}

verif_postfix() {
DESCRIPTION="2.2.18 Ensure mail transfer agent is configured for local-only mode"
echo "**** $DESCRIPTION"
}

impl_postfix() {
DESCRIPTION="2.2.18 Ensure mail transfer agent is configured for local-only mode"
echo "**** $DESCRIPTION"

CHANGE_POSTFIX=`cat $FILE_SSH|sed '1{p;s~.*~inet_interfaces=loopback-only~;h;d};/^.*inet_interfaces/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >${FILE_POSTFIX}.tmp && echo "OK" ||echo "ERROR"`
if [ "$CHANGE_POSTFIX" != "ERROR" ]
then
 mv ${FILE_POSTFIX}.tmp ${FILE_POSTFIX}
else
 echo "POSTFIX $CHANGE_POSTFIX"
fi

}

verif_aide() {
DESCRIPTION="Verificando 1.4.1   Asegúrese de que AIDE esté instalado"
echo "**** $DESCRIPTION"
AIDE=`rpm -qa|grep aide`

if [ "$AIDE" != "" ]
 then
  STATUS="AIDE ESTA INSTALADO"
 else
  STATUS="AIDE NO ESTA INSTALADO"
fi
# falta verificar cron y archivos de configuracion
}


verif_secure_boot() {
DESCRIPTION="Verificando 1.5 Configurar el boot de manera segura"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

impl_grub2() {
DESCRIPTION="Implementando 1.5.1   Asegúrese de que los permisos en la configuración del bootloader estén configurados"
echo "**** $DESCRIPTION"
if [ -f /boot/grub2/grub.cfg ]
then
 chown root:root /boot/grub2/grub.cfg
 chmod og-rwx /boot/grub2/grub.cfg
 chown root:root /boot/grub2/grubenv
 chmod 600 /boot/grub2/grubenv
 chmod og-rwx /boot/grub2/grubenv
else
 STATUS="NO EXISTE /boot/grub2/grub.cfg"
fi
}

impl_grub2_passwd() {
DESCRIPTION="Implementando 1.5.2   Asegúrese de que la contraseña del gestor de arranque (bootloader) esté establecida"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

impl_grub2_uniq() {
DESCRIPTION="Implementando 1.5.3   Garantizar la autenticación requerida para el modo de usuario único"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

verif_limits() {
DESCRIPTION="Verificando 1.6.1   Restringir los Core Dumps"
echo "**** $DESCRIPTION"

if [ "$VER" == "7" -o "$VER" == "6" -o "$VER" == "8" -o "$DISTRIB" == "SUSE" ]
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
DESCRIPTION="Modificando 1.6.1   Restringir los Core Dumps"
echo "**** $DESCRIPTION"
if [ "$VER" == "7" -o "$VER" == "6" -o "$VER" == "8" -o "$DISTRIB" == "SUSE" ]
 then
   echo "$FILE_LIMITS"|tr "|" "\n"|while read LIMIT
    do
     ACTION=`echo $LIMIT|awk '{print $1}'`
     echo "$ACTION"
     if [ "$ACTION" == "EXEC" ]
      then
       ARG_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f1`
       VAL_CORE=`echo $LIMIT|awk '{print $4}'|tr "#" " "|cut -d"=" -f2`
       echo "$ARG_CORE $VAL_CORE"
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
CORE_ARG="Storage=none|ProcessSizeMax=0"
FILE_CORE="/etc/systemd/coredump.conf"
  
if [ -f "${FILE_CORE}" ]
 then
  echo "$CORE_ARG"|tr "|" "\n"|while read CARG
   do
    CHK=`grep "^${CARG}" $FILE_CORE >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
    if [ "$CHK" == "ERROR" ]
     then
      echo "$CARG" >> $FILE_CORE
     else
      echo "$CARG ESTA SETEADO"
    fi
  done
  systemctl daemon-reload
else
  echo "${FILE_CORE} NO EXISTE"
fi
}

verif_sysctl() {
DESCRIPTION="Verficando 1.6.2   Asegúrese de que la aleatorización del diseño del espacio de direcciones (ASLR) esté habilitada"
echo "**** $DESCRIPTION"

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
DESCRIPTION="Modificando 1.6.2   Asegúrese de que la aleatorización del diseño del espacio de direcciones (ASLR) esté habilitada"
echo "**** $DESCRIPTION"

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

verif_selinux() {
DESCRIPTION="Verificando 1.7.1.1 Asegúrese de que SELinux esté instalado/ incluye 1.7.1.4/1.7.1.5/1.7.1.6/1.7.1.7"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
#rpm -q libselinux
}

impl_selinux() {
DESCRIPTION="Verificando 1.7.1.1 Asegúrese de que SELinux esté instalado/ incluye 1.7.1.4/1.7.1.5/1.7.1.6/1.7.1.7"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
#yum install libselinux
}

verif_banner() {
DESCRIPTION="Verificando 1.8.1   Banners de advertencia de línea de comando"
echo "**** $DESCRIPTION"
for X in $FILE_MOTD $FILE_ISSUE $FILE_ISSUE_NET
 do
  VERIF_BANN=`grep "Todo uso no autorizado o divulgacion de la informacion de este sistema dara" $X >/dev/null 2>&1 && echo "$X OK" || echo "$X BANNER NO SET"`
  echo "$VERIF_BANN"
done
}


impl_banner() {
DESCRIPTION="Modificando 1.8.1   Banners de advertencia de línea de comando"
echo "**** $DESCRIPTION"

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

verif_update() {
DESCRIPTION="Verificando 1.9 Asegúrese de instalar actualizaciones, parches y software de seguridad adicional"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

impl_update() {
DESCRIPTION="Modificando 1.9 Asegúrese de instalar actualizaciones, parches y software de seguridad adicional"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

verif_cripto() {
DESCRIPTION="Verificando 1.10 Asegúrese de que la política de cifrado system-wide no sea heredada / incluye 1.11"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

impl_cripto() {
DESCRIPTION="Modificando 1.10 Asegúrese de que la política de cifrado system-wide no sea heredada /incluye 1.11"
STATUS="NO SE IMPLEMENTA"
echo "**** $DESCRIPTION"
}

verif_remove_pkg() {
DESCRIPTION="1.13.2 Asegúrese de que el sistema X Window no esté instalado"
echo "**** $DESCRIPTION"
X_EXT=`rpm -qa|grep -iE xorg-x11-server >/dev/null && echo "X_NO_INSTALADO" || echo "X_INSTALADO"`
echo "X_STATUS = $X_EXT"
}


impl_remove_pkg() {
DESCRIPTION="1.13.2 Asegúrese de que el sistema X Window no esté instalado / xinetd / ypbind / telnet"
echo "**** $DESCRIPTION"

#X_EXT=`rpm -qa|grep -i xorg-x11-server >/dev/null && echo "X_INSTALADO" || echo "X_NO_INSTALADO"`
#if [ "$X_EXT" == "X_INSTALADO" ]
# then
if [ "$DISTRIB" == "SUSE" ]
then
 package="xinetd ypbind telnet cups samba net-snmp rsync"
else
 package="xorg xinetd ypbind telnet"
fi

for i in `echo $package`
do
 echo $i
 rpm -qa | grep -i "$i"|while read line
 do
  echo "rpm -e --nodeps $line"
  rpm -e --nodeps $line
done
done
#fi
verif_remove_pkg
}

verif_ntp() {
DESCRIPTION="Verificando 2.2.1.2 Asegúrese de que chrony/ntp esté configurado"
echo "**** $DESCRIPTION"
for NTP_FILET in $FILE_NTP
do
  if [ -f "$NTP_FILET" ]
   then
    FILE_NTP="$NTP_FILET"
  fi
done

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
DESCRIPTION="Implementando 2.2.1.2 Asegúrese de que chrony/ntp esté configurado"
echo "**** $DESCRIPTION"
for NTP_FILET in $FILE_NTP
do
  if [ -f "$NTP_FILET" ]
   then
    FILE_NTP="$NTP_FILET"
  fi
done

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
FILE_CHRONY=/etc/sysconfig/chronyd
echo "# Command-line options for chronyd " >$FILE_CHRONY
echo "OPTIONS=\"-u chrony\"" >>$FILE_CHRONY
}

verif_services() {
DESCRIPTION="Verificando 1.13 Servicos de Propósito Especial / deshabilita: avahi-daemon cups dhcpd slapd nfs nfsloc rpcgssd rpcidmapd portmap rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd openldap-servers dhcp net-snmp rsh-server talk-server telnet-server tftp / habilita: auditd rsyslog crond / rechaza: httpd nfs rpcbind smb dovecot squid vsftpd nfsloc rpcgssd rpcidmapd portmap /remueve: dhcp openldap-servers bind httpd dovecot samba squid net-snmp ypserv rsh-server talk-server telnet-server tftp"
echo "**** $DESCRIPTION"

for LSERV in $SERVICES_DISABLE $SERVICES_ENABLE
 do
   if [ "$VER" -lt "7" ]
    then
     SERV_STAT=`chkconfig --list $LSERV 2>/dev/null|grep ":on" >/dev/null 2>&1 && echo "UP" ||echo "DOWN"`
     echo "$LSERV $SERV_STAT"
   else
     SERV_STAT=`systemctl is-enabled $LSERV 2>/dev/null|grep -i "enable" >/dev/null 2>&1 && echo "UP" ||echo "DOWN"`
     echo "$LSERV $SERV_STAT"
  fi
done
}

impl_services() {
DESCRIPTION="Modifica 1.13 Servicos de Propósito Especial / deshabilita: avahi-daemon cups dhcpd slapd nfs nfsloc rpcgssd rpcidmapd portmap rpcbind named vsftpd httpd dovecot smb squid snmpd ypserv rsh.socket rlogin.socket rexec.socket ntalk telnet.socket tftp.socket rsyncd openldap-servers dhcp net-snmp rsh-server talk-server telnet-server tftp / habilita: auditd rsyslog crond / rechaza: httpd nfs rpcbind smb dovecot squid vsftpd nfsloc rpcgssd rpcidmapd portmap /remueve: dhcp openldap-servers bind httpd dovecot samba squid net-snmp ypserv rsh-server talk-server telnet-server tftp"
echo "**** $DESCRIPTION"

for LSERV in $SERVICES_DISABLE
 do
  REFUSED=`echo $SERVICES_REFUSED|grep $LSERV >/dev/null 2>&1 && echo "YES" ||echo "NO"`
  if [ "$REFUSED" == "NO" ]
   then
   if [ "$VER" -lt "7" ]
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
       SERV_DISABLE=`systemctl --now disable $LSERV >/dev/null 2>&1 && echo "OK" || echo "FAIL"`
       echo "$LSERV DISABLE $SERV_DISABLE"
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
     if [ "$VER" -lt "7" ]
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



verif_net(){
DESCRIPTION="Verificando 3 Configuración de Red / deshabilita: net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv6.conf.all.forwarding net.ipv6.conf.all.accept_source_route net.ipv6.conf.default.accept_source_route net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects / habilita: net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.tcp_syncookies net.icmp_echo_ignore_broadcasts net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter"
echo "**** $DESCRIPTION"

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
DESCRIPTION="Modificando 2.1 Servicios inetd / 2.1.1 Asegúrese de que los servicios de chargen no estén habilitados – Level 1 / 2.1.2 Asegúrese de que los servicios daytime NO están habilitados – Level 1 / 2.1.3 Asegúrese de que los servicios discard no estén habilitados – Level 1 / 2.1.4 Asegúrese de que los servicios de echo no estén habilitados – Level 1 / 2.1.5 Asegúrese de que los servicios time no estén habilitados – Level 1 / 2.1.6 Asegúrese de que el servidor rsh no esté habilitado – Level 1 / 2.1.7 Asegúrese de que el servidor talk no esté habilitado – Level 1  / 2.1.8 Asegúrese de que el servidor telnet no esté habilitado – Level 1 / 2.1.9 Asegúrese de que el servidor tftp no esté habilitado – Level 1 / 2.1.10 Asegúrese de que el servicio rsync no esté habilitado – Level 1  / 2.1.11 Asegúrese de que xinetd no esté habilitado – Level 1"
echo "**** $DESCRIPTION"

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
  FLUSH6=`/sbin/sysctl -w net.ipv6.route.flush=1 >/dev/null && echo "OK" || echo "NO"`
  echo "FLUSH $FLUSH"
  echo "FLUSH6 $FLUSH6"
}

verif_firewall() {
DESCRIPTION="Verificando 1.18 Configuración del Firewall"
STATUS="No se configura"
echo "**** $DESCRIPTION"
}

impl_firewall() {
DESCRIPTION="Modificando 1.18 Configuración del Firewall"
STATUS="No se configura"
echo "**** $DESCRIPTION"
}

verif_wireless() {
DESCRIPTION="Verificando 1.19 Asegúrese de que las interfaces inalámbricas estén deshabilitadas"
echo "**** $DESCRIPTION"

WL_DEVICE=`ifconfig -a|grep "^wl"|awk '{print $1}'|cut -d: -f1`
if [ "$WL_DEVICE" != "" ]
 then
  WL_STATE=`ifconfig $WL_DEVICE|grep "UP" >/dev/null && echo "UP" || echo "DOWN"`
  WL_IP=`ifconfig $WL_DEVICE|grep "inet "|awk '{print $2}'`
fi
echo "WIRELESS $WL_DEVICE $WL_STATE $WL_IP"
}

impl_wireless() {
DESCRIPTION="Modificando 1.19 Asegúrese de que las interfaces inalámbricas estén deshabilitadas"
echo "**** $DESCRIPTION"
WL_DEVICE=`ifconfig -a|grep "^wl"|awk '{print $1}'|cut -d: -f1`
if [ "$WL_DEVICE" != "" ]
 then
  WL_STATE=`ifconfig $WL_DEVICE|grep "UP" >/dev/null && echo "UP" || echo "DOWN"`
  WL_IP=`ifconfig $WL_DEVICE|grep "inet "|awk '{print $2}'`
  WL_DISABLE=`nmcli radio all off`
  echo "ifdown WL_DEVICE"
  echo "rm /etc/sysconfig/network-scripts/ifcfg-$WL_DEVICE"
  rm /etc/sysconfig/network-scripts/ifcfg-$WL_DEVICE
  nmcli radio all off
 else
  nmcli radio all off
fi
echo "WIRELESS $WL_DEVICE $WL_STATE $WL_IP"
}

verif_grub2_cfg() {
DESCRIPTION="Verificando 1.20 Deshabilitar IPv6 / 1.1.2.3 Asegúrese de que la auditoría de procesos que comienzan antes de la auditd esté habilitada / 1.1.2.4 Asegúrese de que audit_backlog_limit sea suficiente / 1.5.2   Asegúrese de que la contraseña del gestor de arranque (bootloader) esté establecida (NO_APLICA) / 1.7.1.2 Asegúrese de que SELinux no esté deshabilitado en la configuración bootloader (NO_APLICA)"
echo "**** $DESCRIPTION"

for VALUE in $GRUB2_SET
 do
  GRUB2_STAT=`grep GRUB_CMDLINE_LINUX $FILE_GRUB2|grep $VALUE >/dev/null 2>&1 && echo "$VALUE OK" || echo "$VALUE ERROR"`
  echo "$GRUB2_STAT"
done
}

impl_grub2_cfg() {
DESCRIPTION="Modificando 1.20 Deshabilitar IPv6 / 1.1.2.3 Asegúrese de que la auditoría de procesos que comienzan antes de la auditd esté habilitada / 1.1.2.4 Asegúrese de que audit_backlog_limit sea suficiente / 1.5.2   Asegúrese de que la contraseña del gestor de arranque (bootloader) esté establecida (NO_APLICA) / 1.7.1.2 Asegúrese de que SELinux no esté deshabilitado en la configuración bootloader (NO_APLICA)"
echo "**** $DESCRIPTION"

echo $GRUB2_SET|tr "|" " "|while read VALUE
 do
  GRUB2_STAT=`grep GRUB_CMDLINE_LINUX $FILE_GRUB2|grep $VALUE >/dev/null 2>&1 && echo "$VALUE OK" || echo "$VALUE ERROR"`
  echo "$GRUB2_STAT"
  if [ "$GRUB2_STAT" == "$VALUE ERROR" ]
   then
    echo "GRUB_CMDLINE_LINUX=\"${VALUE}\"" >/etc/default/grub
  fi
done
#grub2-mkconfig -o ${FILE_GRUB2}
#grub2-mkconfig -o /boot/grub2/grub.cfg
KERN=`grub2-editenv - list | grep kernelopts`
echo $GRUB2_SET|tr "|" "\n"|while read set
do
  echo "grub2-editenv - set \"$KERN $set\""
  VAR_SET=`echo $KERN|grep $set >/dev/null 2>&1 && echo "OK"|| echo "ERROR"`
  if [ "$VAR_SET" == "ERROR" ]
   then
    echo "grub2-editenv - set \"$KERN $set\""
    grub2-editenv - set "$KERN $set"
    KERN=`grub2-editenv - list | grep kernelopts`
 fi
done 
}


verif_shadow(){
DESCRIPTION="Verificando 4 Registro y auditoría / 1.21 Configurar System Accounting" 
echo "**** $DESCRIPTION"

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

verif_audit() {
DESCRIPTION="Verificando 1.1.3 Configurar retención de datos /1.1.3.1 Asegúrese de que el tamaño del almacenamiento del registro de auditoría esté configurado /1.1.3.2 Asegúrese de que los registros de auditoría no se eliminen automáticamente / 1.1.3.3 Asegúrese de que el sistema esté deshabilitado cuando los registros de audit estén llenos"
echo "**** $DESCRIPTION"

AUDIT_SIZE_LOG=`grep "max_log_file " $FILE_AUDIT|awk '{print $3}'`
AUDIT_LOG_ACTION=`grep "max_log_file_action " $FILE_AUDIT|awk '{print $3}'`
AUDIT_SPACE_LEFT=`grep "space_left_action " $FILE_AUDIT|awk '{print $3}'`
AUDIT_ACTION_MAIL=`grep "action_mail_acct " $FILE_AUDIT|awk '{print $3}'`
AUDIT_ADMIN_SPACE_LEFT=`grep "admin_space_left_action " $FILE_AUDIT|awk '{print $3}'`

if [ "$AUDIT_SIZE_LOG" -lt "100" ]
 then
   echo "Audit max_log_file es menor que lo requerido: $AUDIT_SIZE_LOG"
 else
   echo "Audit max_log_file OK $AUDIT_SIZE_LOG"
fi
if [ "$AUDIT_LOG_ACTION" != "keep_logs" ]
 then
  echo "Audit max_log_file_action tiene el valor = $AUDIT_LOG_ACTION"
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_LOG_ACTION OK"
fi
if [ "$AUDIT_SPACE_LEFT" != "email" ]
 then
  echo "Audit max_log_file_action tiene el valor = $AUDIT_SPACE_LEFT"
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_SPACE_LEFT OK"
fi
if [ "$AUDIT_ACTION_MAIL" != "root" ]
 then
  echo "Audit max_log_file_action tiene el valor = $AUDIT_ACTION_MAIL"
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_ACTION_MAIL OK"
fi
if [ "$AUDIT_ADMIN_SPACE_LEFT" != "halt" ]
 then
  echo "Audit max_log_file_action tiene el valor = $AUDIT_ADMIN_SPACE_LEFT"
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_ADMIN_SPACE_LEFT OK"
fi

}

impl_audit() {
DESCRIPTION="Modificando 1.1.3 Configurar retención de datos /1.1.3.1 Asegúrese de que el tamaño del almacenamiento del registro de auditoría esté configurado / 1.1.3.2 Asegúrese de que los registros de auditoría no se eliminen automáticamente /1.1.3.3 Asegúrese de que el sistema esté deshabilitado cuando los registros de audit estén llenos"
echo "**** $DESCRIPTION"

AUDIT_SIZE_LOG=`grep "max_log_file " $FILE_AUDIT|awk '{print $3}'`
AUDIT_LOG_ACTION=`grep "max_log_file_action " $FILE_AUDIT|awk '{print $3}'`
AUDIT_SPACE_LEFT=`grep "space_left_action " $FILE_AUDIT|awk '{print $3}'`
AUDIT_ACTION_MAIL=`grep "action_mail_acct " $FILE_AUDIT|awk '{print $3}'`
AUDIT_ADMIN_SPACE_LEFT=`grep "admin_space_left_action " $FILE_AUDIT|awk '{print $3}'`


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

if [ "$AUDIT_LOG_ACTION" != "keep_logs" -o "$AUDIT_LOG_ACTION" != "" ]
 then
  AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/max_log_file_action =.*/max_log_file_action = keep_logs/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
  if [ "$AUDIT_MODIF" == "OK" ]
  then
   AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF $AUDIT_MOVE"
  else
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF"
  fi
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_LOG_ACTION OK"
fi

if [ "$AUDIT_SPACE_LEFT" != "email" ]
 then
  AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/space_left_action =.*/space_left_action = email/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
  if [ "$AUDIT_MODIF" == "OK" ]
  then
   AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF $AUDIT_MOVE"
  else
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF"
  fi
 else
  echo "Audit space_left_action tiene el valor = $AUDIT_SPACE_LEFT OK"
fi

if [ "$AUDIT_ACTION_MAIL" != "root" ]
 then
  AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/max_log_file_action =.*/max_log_file_action = root/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
    if [ "$AUDIT_MODIF" == "OK" ]
  then
   AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF $AUDIT_MOVE"
  else
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF"
  fi
 else
  echo "Audit max_log_file_action tiene el valor = $AUDIT_ACTION_MAIL OK"
fi

if [ "$AUDIT_ADMIN_SPACE_LEFT" != "halt" ]
 then
  AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/admin_space_left_action =.*/admin_space_left_action = halt/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
    if [ "$AUDIT_MODIF" == "OK" ]
  then
   AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF $AUDIT_MOVE"
  else
   echo "Modificacion $FILE_AUDIT $AUDIT_MODIF"
  fi
 else
  echo "Audit admin_space_left_action tiene el valor = $AUDIT_ADMIN_SPACE_LEFT OK"
  AUDIT_MODIF=`cat $FILE_AUDIT|sed -e 's/admin_space_left_action =.*/admin_space_left_action = halt/g' >$FILE_AUDIT.tmp && echo "OK" || echo "ERROR"`
  AUDIT_MOVE=`mv -f $FILE_AUDIT.tmp $FILE_AUDIT && echo "MV OK" ||echo "MV ERRROR"`
fi
}

verif_audit_8() {
DESCRIPTION="Verificando 1.1.4 Asegúrese de que se recopilen los cambios en el alcance de la administración del sistema (sudoers) Level 2/ 1.1.5 Asegúrese deque se recopilan los eventos de inicio y cierre de sesión – Level 2 / 1.1.6 Asegúrese de  que se recopile la información de inicio de sesión -Level 2 / 1.1.7 Asegúrese de que se recopilen eventos que modifiquen la información de fecha y hora – Level 2 / 1.1.8 Asegúrese de que se recopilan los eventos que modifican los controles de acceso obligatorios del sistema – Level 2 / 1.1.9 Asegúrese de que se recopilan los eventos que modifican el entorno de red del sistema – Level 2 / 1.1.10 Asegúrese de  que se recopilen los eventos de modificación de permisos de control de acceso discrecional – Level 2 / 1.1.11 Asegúrese de que se recopilen intentos de acceso a archivos no autorizados sin éxito – Level 2 / 1.1.12 Asegúrese de que se recopilan los eventos que modifican la información del usuario / grupo – Level 2 / 1.1.13 Asegúrese de que se recopilan los montajes exitosos del sistema de archivos – Level 2 / 1.1.14 Asegúrese de que se recopile el uso de comandos privilegiados – Level 2 / 1.1.15 Asegúrese de  que los usuarios eliminen los eventos para la eliminación de archivos – Level 2 / 1.1.16 Asegúrese de que se recopile la carga y descarga del módulo del Kernel – Level 2 / 1.1.17 Asegúrese de que se recopilen las acciones del administrador del sistema (sudolog) – Level 2 / 1.1.18 Asegúrese de que la configuración de auditoría sea inmutable – Level 2"
echo "**** $DESCRIPTION"

for OC in $FILES_AUDIT_8
 do
  FILE_A_8=`echo $OC|cut -d":" -f2`
  if [ -f "$FILE_A_8" ]
   then
    echo "###### $FILE_A_8"
    cat $FILE_A_8
   else
    echo "##### $FILE_A_8 NO_EXISTE"
   fi
done
}


impl_audit_8() {
DESCRIPTION="Implementando 1.1.4 Asegúrese de que se recopilen los cambios en el alcance de la administración del sistema (sudoers) Level 2/ 1.1.5 Asegúrese deque se recopilan los eventos de inicio y cierre de sesión – Level 2 / 1.1.6 Asegúrese de  que se recopile la información de inicio de sesión -Level 2 / 1.1.7 Asegúrese de que se recopilen eventos que modifiquen la información de fecha y hora – Level 2 / 1.1.8 Asegúrese de que se recopilan los eventos que modifican los controles de acceso obligatorios del sistema – Level 2 / 1.1.9 Asegúrese de que se recopilan los eventos que modifican el entorno de red del sistema – Level 2 / 1.1.10 Asegúrese de  que se recopilen los eventos de modificación de permisos de control de acceso discrecional – Level 2 / 1.1.11 Asegúrese de que se recopilen intentos de acceso a archivos no autorizados sin éxito – Level 2 / 1.1.12 Asegúrese de que se recopilan los eventos que modifican la información del usuario / grupo – Level 2 / 1.1.13 Asegúrese de que se recopilan los montajes exitosos del sistema de archivos – Level 2 / 1.1.14 Asegúrese de que se recopile el uso de comandos privilegiados – Level 2 / 1.1.15 Asegúrese de  que los usuarios eliminen los eventos para la eliminación de archivos – Level 2 / 1.1.16 Asegúrese de que se recopile la carga y descarga del módulo del Kernel – Level 2 / 1.1.17 Asegúrese de que se recopilen las acciones del administrador del sistema (sudolog) – Level 2 / 1.1.18 Asegúrese de que la configuración de auditoría sea inmutable – Level 2"
echo "**** $DESCRIPTION"

for OC in `echo $FILES_AUDIT_8`
 do
  VAR8=`echo $OC|cut -d":" -f1`
  FILE_A_8=`echo $OC|cut -d":" -f2`
  echo "#Archivo creado y modificado por el script de SOX:  $DATE" >$FILE_A_8
  echo "${!VAR8}"|tr "|" "\n" >>$FILE_A_8
  #echo "${!VAR8}"|tr "|" "\n"
  echo "${!VAR8}"|tr "|" "\n"|while read audit_line
  do
   #auditctl ${audit_line}
   echo "auditctl $audit_line"
  done
done

echo "#Archivo creado y modificado por el script de SOX:  $DATE" >/etc/audit/rules.d/12-privileged.rules
find /usr -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>='"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' -F auid!=4294967295 -k privileged" }'  >> /etc/audit/rules.d/12-privileged.rules
service auditd restart
}

verif_journal() {
DESCRIPTION="Verificando 4.2.2.1 Asegúrese de que journald esté configurado para enviar registros a Rsyslog – Level 1 / 4.2.2.2	Asegúrese de que journald esté configurado para comprimir archivos de registro grandes – Level 1 / 4.2.2.3 Asegúrese de que journald esté configurado para escribir archivos de registro en el disco persistente – Level 1 / 4.2.3 Asegúrese de que los permisos en todos los archivos de registro estén configurados – Level 1"
echo "**** $DESCRIPTION"

for ATTR in `echo $JOURNAL_ATTR|tr "|" "\n"`
 do
  VARJ=`echo $ATTR|cut -d"=" -f1`
  grep -e "^\s*${VARJ}" $FILE_JOURNAL >/dev/null 2>&1 && echo "$VARJ OK" || echo "$VARJ ERROR"
done
}

impl_journal() {
DESCRIPTION="Modificando 4.2.2.1 Asegúrese de que journald esté configurado para enviar registros a Rsyslog – Level 1 / 4.2.2.2 Asegúrese de que journald esté configurado para comprimir archivos de registro grandes – Level 1 / 4.2.2.3 Asegúrese de que journald esté configurado para escribir archivos de registro en el disco persistente – Level 1 / 4.2.3 Asegúrese de que los permisos en todos los archivos de registro estén configurados – Level 1 / 1.1.28 Verificar que los permisos en /etc/ssh/sshd_config estén configurados – Level "
echo "**** $DESCRIPTION"

for ATTR in `echo $JOURNAL_ATTR|tr "|" "\n"`
 do
  VARJ=`echo $ATTR|cut -d"=" -f1`
  JOURNAL_CHANGE=`cat $FILE_JOURNAL|sed '1{p;s~.*~'$ATTR'~;h;d};/^.*'$VARJ'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_JOURNAL.tmp && echo "OK" ||echo "ERROR"`
  mv $FILE_JOURNAL.tmp $FILE_JOURNAL
  echo "$VARJ $JOURNAL_CHANGE"
done
}

verif_cron() {
DESCRIPTION="5.1 Configure cron / 5.1.1 Verificar que cron daemon esté habilitado – Level 1 / 5.1.2 Asegúrese de que los permisos en /etc/crontab estén configurados – Level 1  / 5.1.3 Asegúrese de que los permisos en /etc/cron.hourly estén configurados – Level 1  / 5.1.4 Asegúrese de que los permisos en /etc/cron.daily estén configurados – Level 1 / 5.1.5 Asegúrese de que los permisos en /etc/cron.weekly estén configurados - Level 1 / 5.1.6 Asegúrese de que los permisos en /etc/cron.monthly estén configurados - Level 1 / 5.1.7 Asegúrese de que los permisos en /etc/cron.d estén configurados – Level 1 / 5.1.8 Asegúrese de que at / cron esté restringido a usuarios autorizados – Level 1"
echo "**** $DESCRIPTION"

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
DESCRIPTION="Implementando 1.1.21 Verificar que los permisos en /etc/crontab estén configurados – Level 1 / 1.1.22 Verificar que los permisos en /etc/cron.hourly estén configurados – Level 1 / 1.1.24 Verificar que los permisos en /etc/cron.weekly estén configurados – Level 1 / 1.1.26 Verificar que los permisos en /etc/cron.d estén configurados – Level 1 / 1.1.27 Verificar que at/cron esté restringido a usuarios autorizados – Level 1 / 1.1.28 Verificar que los permisos en /etc/ssh/sshd_config estén configurados – Level"
echo "**** $DESCRIPTION"


GROUP_WHEEL=`cat /etc/group|sed '1{p;s~.*~wheel:x:10:gestkeyh,root~;h;d};/^.*wheel/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >/tmp/group.tmp && echo "OK" || echo "ERROR"`

if [ ${GROUP_WHEEL} == "OK" ]
 then
  mv /tmp/group.tmp /etc/group
fi

#GROUP_SHADOW=`cat /etc/group|sed '1{p;s~.*~shadow:x:15:~;h;d};/^.*shadow/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >/tmp/group.tmp && echo "OK" || echo "ERROR"`
if [ ${GROUP_SHADOW} == "OK" ]
 then
  mv /tmp/group.tmp /etc/group
fi


chage -M -1 gestkeyh
chage -E -1 gestkeyh

echo $GENERAL_ABM|tr "|" "\n"|while read FL ACT
do
  echo "$ACT $FL"
  ${ACT} ${FL}
done

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

verif_find() {
DESCRIPTION="Verifica 4.2.3 Asegúrese de que los permisos en todos los archivos de registro estén configurados – Level 1 / 1.1.30 Verificar que los permisos en los archivos de clave de host privado SSH estén configurados – Level 1 / 1.1.31 Asegúrese de que los permisos en los archivos de clave de host público SSH estén configurados – Level 1"
echo "**** $DESCRIPTION"

find /var/log -type f -perm /037 -ls -o -type d -perm /026 -ls
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;
}

impl_find() {
DESCRIPTION="Implementa 4.2.3 Asegúrese de que los permisos en todos los archivos de registro estén configurados – Level 1 / 1.1.30 Verificar que los permisos en los archivos de clave de host privado SSH estén configurados – Level 1"
echo "**** $DESCRIPTION"

#find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
for X in `df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002`; do chmod 640 $X; done
for X in `df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup`; do chgrp root $X; done
for X in `df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser`; do chown root $X; done
find /var/log -type f -exec chmod 640 "{}" \;
find /var/log -type d -exec chmod 750 "{}" \;
}

verif_ibmunx_user() {
DESCRIPTION="Verifica que el usuario ibmunx exista"
echo "**** $DESCRIPTION"

   spkey_ibmunx
   USERI=`cat /etc/passwd|grep ibmunx >/dev/null 2>&1 && echo "ibmunx:OK" || echo "ibmunx:NO_EXISTE"`
   KEYI=`grep "${KIBMUNX}" /home/ibmunx/.ssh/authorized_keys  >/dev/null  2>&1 && echo "ibmunx_key:OK" || echo "ibmunx_key:NO_EXISTE"`
   SRV_K=`uname -n`
   echo "$SRV_K|$USERI|$KEYI"
}

impl_ibmunx() {
verif_ibmunx_user
DESCRIPTION="Implementa la creación del usuario ibmunx"
echo "**** $DESCRIPTION"

  if [ "$USERI" == "ibmunx:NO_EXISTE" ]
   then
    groupadd ibmunx
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
verif_ibmunx_user
DESCRIPTION="Verifica 1.1.29 Verificar el acceso SSH es limitado Level 1 NO_SE_IMPLEMENTA / 1.1.31 Asegúrese de que los permisos en los archivos de clave de host público SSH estén configurados – Level 1 / 1.1.33 Verificar que el reenvío SSH X11 esté deshabilitado – Level 2 / 1.1.34 Verificar que SSH MaxAuthTries esté establecido en 4 o menos – Level 1 / 1.1.35 Verificar que SSH IgnoreRhosts esté habilitado – Level 1 / 1.1.36 Asegúrese de que SSH HostbasedAuthentication esté deshabilitado – Level 1 / 1.1.37 Verificar que el inicio de sesión root SSH esté deshabilitado – Level 1 / 1.1.38 Asegúrese de que SSH PermitEmptyPasswords esté deshabilitado – Level 1 / 1.1.39 Verificar que SSH PermitUserEnvironment esté deshabilitado – Level 1 / 1.1.40 Verificar que el intervalo de tiempo de espera inactivo SSH esté configurado – Level 1 / 1.1.41 Verificar que SSH LoginGraceTime esté configurado en un minuto o menos – Level 1 / 1.1.42 Verificar que el banner de advertencia SSH esté configurado – Level 1 / 1.1.43 Verificar que SSH PAM esté habilitado – Level 1 / 1.1.44 Verificar que SSH AllowTcpForwarding esté deshabilitado – Level 2 / 1.1.45 Verificar que SSH MaxStartups esté configurado – Level 1 / 1.1.46 Verificar que SSH MaxSessions esté configurado en 4 o menos – Level 1 / 1.1.47 Verificar que la política de cifrado de todo el sistema no se anule – Level 1"
echo "**** $DESCRIPTION"

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
verif_ibmunx_user
DESCRIPTION="Implementa 1.1.29 Verificar el acceso SSH es limitado Level 1 NO_SE_IMPLEMENTA / 1.1.31 Asegúrese de que los permisos en los archivos de clave de host público SSH estén configurados – Level 1 / 1.1.33 Verificar que el reenvío SSH X11 esté deshabilitado – Level 2 / 1.1.34 Verificar que SSH MaxAuthTries esté establecido en 4 o menos – Level 1 / 1.1.35 Verificar que SSH IgnoreRhosts esté habilitado – Level 1 / 1.1.36 Asegúrese de que SSH HostbasedAuthentication esté deshabilitado – Level 1 / 1.1.37 Verificar que el inicio de sesión root SSH esté deshabilitado – Level 1 / 1.1.38 Asegúrese de que SSH PermitEmptyPasswords esté deshabilitado – Level 1 / 1.1.39 Verificar que SSH PermitUserEnvironment esté deshabilitado – Level 1 / 1.1.40 Verificar que el intervalo de tiempo de espera inactivo SSH esté configurado – Level 1 / 1.1.41 Verificar que SSH LoginGraceTime esté configurado en un minuto o menos – Level 1 / 1.1.42 Verificar que el banner de advertencia SSH esté configurado – Level 1 / 1.1.43 Verificar que SSH PAM esté habilitado – Level 1 / 1.1.44 Verificar que SSH AllowTcpForwarding esté deshabilitado – Level 2 / 1.1.45 Verificar que SSH MaxStartups esté configurado – Level 1 / 1.1.46 Verificar que SSH MaxSessions esté configurado en 4 o menos – Level 1 / 1.1.47 Verificar que la política de cifrado de todo el sistema no se anule – Level 1"
echo "**** $DESCRIPTION"

cp /etc/sysconfig/sshd /etc/sysconfig/sshd.bck_pre_sox
sed -i 's/^[^#]*CRYPTO_POLICY/#&/' /etc/sysconfig/sshd
sed -ri "s/^\s*(CRYPTO_POLICY\s*=.*)$/#\1/" /etc/sysconfig/sshd

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
echo "auth        required      pam_tally2.so deny=3 onerr=fail"
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
echo "auth      required     pam_env.so"
echo "auth      required     pam_faillock.so preauth audit silent deny=3 unlock_time=1800"
echo "auth      [success=1 default=bad]         pam_unix.so"
echo "auth      [default=die]   pam_faillock.so authfail audit deny=3 unlock_time=1800"
echo "auth      sufficient   pam_faillock.so authsucc audit deny=3 unlock_time=1800"
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

template_password_auth_7(){
echo "#%PAM-1.0"
echo "auth      required     pam_env.so"
echo "auth      required     pam_faillock.so preauth audit silent deny=3 unlock_time=1800"
echo "auth      [success=1 default=bad]         pam_unix.so"
echo "auth      [default=die]   pam_faillock.so authfail audit deny=3 unlock_time=1800"
echo "auth      sufficient   pam_faillock.so authsucc audit deny=3 unlock_time=1800"
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

if [ "$VER" -eq "7" ]
 then
  ## minlen=14 pero lo baje a 8
  AUTH_LINE="pam_cracklib.so try_first_pass retry=3 minlen=8 dcredit=-2 ucredit=-1 ocredit=-1 lcredit=-1 difok=3 maxrepeats=2"
  VERIF_AUTH=`grep "$AUTH_LINE" $FILE_SYS_AUTH >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  echo "Politica de PASSWORD $FILE_SYS_AUTH $VERIF_AUTH"
  VERIF_TALLY=`grep "pam_tally2" $FILE_SYS_AUTH|grep "deny=3"|grep "onerr=fail" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
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
if [ "$VER" -eq "7" ]
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


verif_authselect() {
DESCRIPTION="Verificando 1.25 Configurar authselect / 1.1.48 Crear perfil de selección automática personalizado – Level 1 / 1.1.49 Seleccionar perfil de selección automática – Level 1 / 1.1.50 Verificar que authselect incluya with-faillock – Level 1"
echo "**** $DESCRIPTION"

AUTHSEL_PROF=`authselect current | grep "Profile ID: custom/" >/dev/null 2>&1 && echo "AUTHSELECT PROFILE EXISTE Y ESTA EN USO OK" ||echo "AUTHSELECT PROFILE EXISTE ERROR"`
echo "$AUTHSEL_PROF"
AUTHSEL_FAILOCK=`authselect current | grep with-faillock >/dev/null 2>&1 && echo "AUTHSELECT with-faillock SETEADO OK" ||echo "AUTHSELECT with-faillock SETEADO ERROR"`

echo "$PAM_VALUE_8"|tr "|" "\n"|while read PAM
 do
  grep "^${PAM}" $FILE_PAM >/dev/null >&1 && echo "$PAM == OK" || echo "$PAM == ERROR"
done
}

impl_authselect() {
DESCRIPTION="Verificando 1.25 Configurar authselect / 1.1.48 Crear perfil de selección automática personalizado – Level 1 / 1.1.49 Seleccionar perfil de selección automática – Level 1 / 1.1.50 Verificar que authselect incluya with-faillock – Level 1"
echo "**** $DESCRIPTION"
authselect select sssd --force
rm -fr /etc/authselect/custom/movistar-sox-profile

mv -f ${FILE_AUTH_PASSWORD_AUTH} ${FILE_AUTH_PASSWORD_AUTH}.old
mv -f ${FILE_AUTH_SYSTEM_AUTH} ${FILE_AUTH_SYSTEM_AUTH}.old
mv -f ${FILE_AUTH_SU_AUTH} ${FILE_AUTH_SU_AUTH}.old

template_password_auth_8 >${FILE_AUTH_PASSWORD_AUTH}
template_system_auth_8 >${FILE_AUTH_SYSTEM_AUTH}
template_su_auth_8 >${FILE_AUTH_SU_AUTH}

AUTHSEL_PROF=`authselect create-profile movistar-sox-profile -b sssd --symlink-meta >/dev/null 2>&1 && echo "AUTHSELECT PROFILE CREACION OK" ||echo "AUTHSELECT PROFILE CREACION ERROR"`
echo "$AUTHSEL_PROF"
AUTHSEL_PROF_SET=`authselect select custom/movistar-sox-profile with-sudo with-faillock >/dev/null 2>&1 && echo "AUTHSELECT PROFILE SET USAGE OK" ||echo "AUTHSELECT PROFILE SET USAGE ERROR"`
echo "$AUTHSEL_PROF_SET"
AUTHSEL_FAILOCK=`authselect select custom/movistar-sox-profile with-sudo with-faillock  >/dev/null 2>&1 && echo "AUTHSELECT with-sudo with-faillock without-nullok SET OK" ||echo "AUTHSELECT with-sudo with-faillock without-nullok SET ERROR"`
echo "$AUTHSEL_FAILOCK"

echo $PAM_VALUE_8|tr "|" "\n"|while read line
 do
  PAM_VARIABLE=`echo $line|cut -d"=" -f1`
  echo "$PAM_VARIABLE"
  PAM_ATTR=`echo $line|cut -d"=" -f2`
  PAM_SET=`grep "^$PAM_VARIABLE" $FILE_PAM|grep "$PAM_ATTR" >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
  if [ "$PAM_SET" == "ERROR" ]
   then
    PAM_CHANGE=`cat $FILE_PAM|sed '1{p;s~.*~'${line}'~;h;d};/^.*'${PAM_VARIABLE}'/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >$FILE_PAM.tmp && echo "OK" ||echo "ERROR"`

    mv $FILE_PAM.tmp $FILE_PAM 2>/dev/null
    chmod 644 $FILE_PAM
    echo "$FILE_PAM  $PAM_VARIABLE == $PAM_CHANGE   $PAM_ATTR"
  fi
done
authselect apply-changes

cp /etc/pam.d/su /etc/pam.d/su.old

#cat /etc/pam.d/su.old|sed '1{p;s~.*~auth            sufficient        pam_wheel.so trust use_uid~;h;d};/^.*auth.*sufficient.*pam_wheel.so.*trust.*use_uid/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >/etc/pam.d/su
}
template_su_auth_8() {
echo "#%PAM-1.0"
echo "auth		required	pam_env.so"
echo "auth		sufficient	pam_rootok.so"
echo "# Uncomment the following line to implicitly trust users in the \"wheel\" group."
echo "#auth		sufficient	pam_wheel.so trust use_uid"
echo "# Uncomment the following line to require a user to be in the \"wheel\" group."
echo "auth		required	pam_wheel.so use_uid"
echo "auth		substack	system-auth"
echo "auth		include		postlogin"
echo "account		sufficient	pam_succeed_if.so uid = 0 use_uid quiet"
echo "account		include		system-auth"
echo "password	include		system-auth"
echo "session		include		system-auth"
echo "session		include		postlogin"
echo "session		optional	pam_xauth.so"
}

template_system_auth_8() {
echo "# Generated by SOX $DATE"
echo "# Do not modify this file manually."
echo ""
echo "auth        required                                     pam_env.so"
echo "auth        required                                     pam_faildelay.so delay=2000000"
#Esta linea la modifique en diciembre 2020
echo "auth        required                                     pam_faillock.so preauth silent deny=3 unlock_time=1800 {include if \"with-faillock\"}"
#########################################
echo "auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet"
echo "auth        [default=1 ignore=ignore success=ok]         pam_localuser.so"
echo "#auth        [success=1 default=bad]                      pam_unix.so"
echo "auth        sufficient                                   pam_unix.so remember=12 try_first_pass                  nullok"
echo "auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success"
echo "auth        sufficient                                   pam_sss.so forward_pass"
echo "auth        required                                     pam_deny.so"
echo ""
echo "account     required                                     pam_unix.so"
echo "account     sufficient                                   pam_localuser.so"
echo "account     sufficient                                   pam_succeed_if.so uid < 1000 quiet"
echo "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
echo "account     required                                     pam_permit.so"
echo ""
echo "password    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3 remember=12"
echo "password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=12"
echo "password    sufficient                                   pam_sss.so use_authtok"
echo "password    required                                     pam_deny.so"
echo ""
echo "session     optional                                     pam_keyinit.so revoke"
echo "session     required                                     pam_limits.so"
echo "-session    optional                                     pam_systemd.so"
echo "session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid"
echo "session     required                                     pam_unix.so"
echo "session     optional                                     pam_sss.so"
}

template_system_auth_8_old() {
echo "{imply \"with-smartcard\" if \"with-smartcard-required\"}"
echo "auth        required                                     pam_env.so"
echo "auth        required                                     pam_faildelay.so delay=2000000"
echo "auth        [default=die]                                pam_faillock.so  				     {include if \"with-faillock\"}"
echo "auth        required                                     pam_faillock.so preauth silent deny=3 unlock_time=1800 {include if \"with-faillock\"}"
echo "auth        [success=1 default=ignore]                   pam_succeed_if.so service notin login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver quiet use_uid {include if \"with-smartcard-required\"}"
echo "auth        [success=done ignore=ignore default=die]     pam_sss.so require_cert_auth ignore_authinfo_unavail   {include if \"with-smartcard-required\"}"
echo "auth        sufficient                                   pam_fprintd.so                                         {include if \"with-fingerprint\"}"
echo "auth        sufficient                                   pam_u2f.so cue                                         {include if \"with-pam-u2f\"}"
echo "auth        required                                     pam_u2f.so cue nouserok                                {include if \"with-pam-u2f-2fa\"}"
echo "auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet"
echo "auth        [default=1 ignore=ignore success=ok]         pam_localuser.so                                       {exclude if \"with-smartcard\"}"
echo "auth        [default=2 ignore=ignore success=ok]         pam_localuser.so                                       {include if \"with-smartcard\"}"
echo "auth        [success=done authinfo_unavail=ignore ignore=ignore default=die] pam_sss.so try_cert_auth           {include if \"with-smartcard\"}"
echo "auth        [success=1 default=bad]                      pam_unix.so"
echo "auth        sufficient                                   pam_unix.so remember=12 try_first_pass                  {if not \"without-nullok\":nullok}"
echo "auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success"
echo "auth        sufficient                                   pam_sss.so forward_pass"
echo "auth        sufficient                                   pam_faillock.so                                       {include if \"with-faillock\"}"
echo "auth        required                                     pam_faillock.so                                       {include if \"with-faillock\"}"
echo "auth        required                                     pam_faillock.so authfail deny=3 unlock_time=1800       {include if \"with-faillock\"}"
echo "auth        required                                     pam_deny.so"
echo ""
#echo "account     required                                     pam_access.so                                          {include if \"with-pamaccess\"}"
echo "account     required                                     pam_faillock.so                                        {include if \"with-faillock\"}"
echo "account     required                                     pam_unix.so"
echo "account     sufficient                                   pam_localuser.so"
echo "account     sufficient                                   pam_succeed_if.so uid < 1000 quiet"
echo "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
echo "account     required                                     pam_permit.so"
echo ""
echo "password    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3 remember=12"
echo "password    sufficient                                   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} try_first_pass use_authtok remember=12"
echo "password    sufficient                                   pam_sss.so use_authtok"
echo "password    required                                     pam_deny.so"
echo ""
echo "session     optional                                     pam_keyinit.so revoke"
echo "session     required                                     pam_limits.so"
echo "-session    optional                                     pam_systemd.so"
echo "session     optional                                     pam_oddjob_mkhomedir.so umask=0077                    {include if \"with-mkhomedir\"}"
echo "session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid"
echo "session     required                                     pam_unix.so"
echo "session     optional                                     pam_sss.so"
}

template_password_auth_8(){
echo "# Generated by SOX $DATE"
echo "# Do not modify this file manually."
echo ""
echo "auth        required                                     pam_env.so"
echo "auth        required                                     pam_faildelay.so delay=2000000"
echo "auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet"
echo "auth        [default=1 ignore=ignore success=ok]         pam_localuser.so"
echo "#auth        [success=1 default=bad]                      pam_unix.so"
echo "auth        sufficient                                   pam_unix.so nullok try_first_pass"
echo "auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success"
echo "auth        sufficient                                   pam_sss.so forward_pass"
echo "auth        required                                     pam_deny.so"
#Esta linea la modifique en diciembre
echo "auth        required                                     pam_faillock.so preauth silent authfail deny=3 unlock_time=1800 {include if \"with-faillock\"}"
####################################
echo ""
echo "account     required                                     pam_unix.so"
echo "account     sufficient                                   pam_localuser.so"
echo "account     sufficient                                   pam_succeed_if.so uid < 1000 quiet"
echo "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
echo "account     required                                     pam_permit.so"
echo ""
echo "password    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3"
echo "password    sufficient                                   pam_unix.so sha512 shadow nullok try_first_pass use_authtok"
echo "password    sufficient                                   pam_unix.so remember=12"
echo "password    sufficient                                   pam_sss.so use_authtok"
echo "password    required                                     pam_deny.so"
echo ""
echo "session     optional                                     pam_keyinit.so revoke"
echo "session     required                                     pam_limits.so"
echo "-session    optional                                     pam_systemd.so"
echo "session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid"
echo "session     required                                     pam_unix.so"
echo "session     optional                                     pam_sss.so"
}

template_password_auth_8_old(){
echo "auth        required                                     pam_env.so"
echo "auth        required                                     pam_faildelay.so delay=2000000"
echo "auth        required                                     pam_deny.so # Smartcard authentication is required     {include if \"with-smartcard-required\"}"
echo "auth        required                                     pam_faillock.so                                        {include if \"with-faillock\"}"
echo "auth        sufficient                                   pam_faillock.so                                        {include if \"with-faillock\"}"
echo "auth        required                                     pam_faillock.so preauth audit silent deny=3 unlock_time=1800 {include if \"with-faillock\"}"
echo "auth        sufficient                                   pam_u2f.so cue                                         {include if \"with-pam-u2f\"}"
echo "auth        required                                     pam_u2f.so cue nouserok                                {include if \"with-pam-u2f-2fa\"}"
echo "auth        [default=1 ignore=ignore success=ok]         pam_succeed_if.so uid >= 1000 quiet"
echo "auth        [default=1 ignore=ignore success=ok]         pam_localuser.so"
echo "auth        [success=1 default=bad]                      pam_unix.so"
echo "auth        sufficient                                   pam_unix.so {if not \"without-nullok\":nullok} try_first_pass"
echo "auth        requisite                                    pam_succeed_if.so uid >= 1000 quiet_success"
echo "auth        sufficient                                   pam_sss.so forward_pass"
echo "auth        required                                     pam_faillock.so authfail deny=3 unlock_time=1800       {include if \"with-faillock\"}"
echo "auth        required                                     pam_deny.so"
echo ""
echo "account     required                                     pam_access.so                                          {include if \"with-pamaccess\"}"
echo "account     required                                     pam_faillock.so                                        {include if \"with-faillock\"}"
echo "auth        [default=die]                                pam_faillock.so                                        {include if \"with-faillock\"}"
echo "account     required                                     pam_unix.so"
echo "account     sufficient                                   pam_localuser.so"
echo "account     sufficient                                   pam_succeed_if.so uid < 1000 quiet"
echo "account     [default=bad success=ok user_unknown=ignore] pam_sss.so"
echo "account     required                                     pam_permit.so"
echo ""
echo "password    requisite                                    pam_pwquality.so try_first_pass local_users_only enforce-for-root retry=3"
echo "password    sufficient                                   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} try_first_pass use_authtok"
echo "password    sufficient                                   pam_unix.so remember=12"
echo "password    sufficient                                   pam_sss.so use_authtok"
echo "password    required                                     pam_deny.so"
echo ""
echo "session     optional                                     pam_keyinit.so revoke"
echo "session     required                                     pam_limits.so"
echo "-session    optional                                     pam_systemd.so"
echo "session     optional                                     pam_oddjob_mkhomedir.so umask=0077                    {include if \"with-mkhomedir\"}"
echo "session     [success=1 default=ignore]                   pam_succeed_if.so service in crond quiet use_uid"
echo "session     required                                     pam_unix.so"
echo "session     optional                                     pam_sss.so"
}


template_common_auth_suse() {
echo "#%PAM-1.0"
echo "#"
echo "# This file is autogenerated by pam-config. All changes"
echo "# will be overwritten."
echo "#"
echo "# Authentication-related modules common to all services"
echo "#"
echo "# This file is included from other service-specific PAM config files,"
echo "# and should contain a list of the authentication modules that define"
echo "# the central authentication scheme for use on the system"
echo "# (e.g., /etc/shadow, LDAP, Kerberos, etc.). The default is to use the"
echo "# traditional Unix authentication mechanisms."
echo "#"
echo "auth	required	pam_env.so	"
echo "auth	optional	pam_gnome_keyring.so"
echo "auth	required	pam_unix.so	sha512 try_first_pass" 
echo "auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900"
}

template_common_account_suse() {
echo "account   required 	pam_tally2.so"
}

template_common_password_suse() {
echo "#%PAM-1.0"
echo "#"
echo "# This file is autogenerated by pam-config. All changes"
echo "# will be overwritten."
echo "#"
echo "# Password-related modules common to all services"
echo "#"
echo "# This file is included from other service-specific PAM config files,"
echo "# and should contain a list of modules that define  the services to be"
echo "# used to change user passwords."
echo "#"
echo "password requisite pam_cracklib.so	 try_first_pass retry=3 minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1"
echo "password	required	pam_pwhistory.so	remember=12"
echo "password	optional	pam_gnome_keyring.so	use_authtok"
echo "password	required	pam_unix.so	use_authtok nullok shadow sha512 try_first_pass"
}

impl_pam_suse() {
# Se tiene que ejecutar despues de impl_cpassword_suse
cp /etc/pam.d/common-auth-pc /etc/pam.d/common-auth-pc.SOX
cp /etc/pam.d/common-account-pc /etc/pam.d/common-account-pc.SOX
cp /etc/pam.d/common-password-pc /etc/pam.d/common-password-pc.SOX

template_common_auth_suse >>/etc/pam.d/common-auth-pc
template_common_account_suse >>/etc/pam.d/common-account-pc
template_common_password_suse >>/etc/pam.d/common-password-pc
awk -v v="pam_cracklib.so" -v o="try_first_pass" '!/^#/ && ($3 == v) { if(!match(o, $3)) $3=$3"\t "o } 1' /etc/pam.d/common-password-pc >/etc/pam.d/common-password-pc-2
mv /etc/pam.d/common-password-pc-2 /etc/pam.d/common-password-pc
echo "auth required pam_wheel.so use_uid" >>/etc/pam.d/su
}



verif_shadow(){
DESCRIPTION="Verificando 4 Registro y auditoría / 1.21 Configurar System Accounting"
echo "**** $DESCRIPTION"

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
echo "chequeando que los usuarios tengan la fecha de cambio de password en el futuro"
for usr in $(cut -d: -f1 /etc/shadow) 
do 
[[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)" 
done
}

impl_shadow(){
DESCRIPTION="Modificando 4 Registro y auditoría / 1.21 Configurar System Accounting"
echo "**** $DESCRIPTION"

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
# obliga a los usuario a cambiar la pass en el proximo login
#awk -F: '( $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $1 != "nfsnobody" ) { print $1 }' /etc/passwd| xargs -n 1 chage -d 0
grep -E '^[^:]+:[^!*]' /etc/shadow|grep -v root | cut -d: -f1,5|tr ":" " "|while read USER PASS_MAX_DAYS
 do
  chage --maxdays 30 $USER
done

grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,4|grep -v root|tr ":" " "|while read USER PASS_MIN_DAYS
 do
  chage --mindays 0 $USER
done

grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,6|grep -v root|tr ":" " "|while read USER PASS_WARN_AGE
 do
  chage --warndays 5 $USER
done

useradd -D -f 30

grep -E ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1,7|grep -v root|tr ":" " "|while read USER INACTIVE
 do
  chage --inactive 30 $USER
done

for usr in $(cut -d: -f1 /etc/shadow)
 do 
  [[ $(chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo "$usr :$(chage --list $usr | grep '^Last password change' | cut -d: -f2)"
done

#Establece todas las cuentas del sistema en un shell sin inicio de sesión
awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print $1}' /etc/passwd | while read user 
  do 
   usermod -s $(which nologin) $user 
  done

# bloquea automáticamente las cuentas del sistema no root
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | while read user 
do 
 usermod -L $user
done

for SET in /etc/bashrc /etc/profile
 do
  PROF=`grep -iE 'TMOUT=1800|export TMOUT' $SET`
  if [ "$PROF" == "" ]
  then
   echo "readonly TMOUT=1800 ; export TMOUT" >>$SET
  else
   echo "$SET CONFIGURADO TMOUT"
  fi
done

SET_ROOT=`grep "^root:" /etc/passwd | cut -f4 -d:`
if [ "$SET_ROOT" -ne "0" ]
 then
  usermod -g 0 root
 else
  echo "Root group 0 OK"
fi

for SET in /etc/bashrc /etc/profile
 do
  PROF=`grep -iE 'umask 027' $SET`
  if [ "$PROF" == "" ]
  then
   UMASK_CH=`cat $SET|sed -e 's/umask .*/umask 027/g' >${SET}.tmp && echo "OK" ||echo "ERROR"`
   if [ "$UMASK_CH" == "OK" ]
    then
     mv ${SET}.tmp ${SET}
   fi
  else
    UMASK_CH=`cat $SET|sed -e 's/umask .*/umask 027/g' >${SET}.tmp && echo "OK" ||echo "ERROR"`
   if [ "$UMASK_CH" == "OK" ]
    then
     mv ${SET}.tmp ${SET}
   fi
   echo "$SET CONFIGURADO umask 027"
  fi
done

#cp /etc/pam.d/su /etc/pam.d/su.old

#cat /etc/pam.d/su.old|sed '1{p;s~.*~auth            required        pam_wheel.so use_uid~;h;d};/^.*auth.*required.*pam_wheel.so.*use_uid/{g;p;s/.*//;h;d;};$G'|sed '$ { /^$/ d}' >/etc/pam.d/su

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

verif_audit_8() {
DESCRIPTION="Verificando 1.1.4 Asegúrese de que se recopilen los cambios en el alcance de la administración del sistema (sudoers) Level 2/ 1.1.5 Asegúrese deque se recopilan los eventos de inicio y cierre de sesión – Level 2 / 1.1.6 Asegúrese de  que se recopile la información de inicio de sesión -Level 2 / 1.1.7 Asegúrese de que se recopilen eventos que modifiquen la información de fecha y hora – Level 2 / 1.1.8 Asegúrese de que se recopilan los eventos que modifican los controles de acceso obligatorios del sistema – Level 2 / 1.1.9 Asegúrese de que se recopilan los eventos que modifican el entorno de red del sistema – Level 2 / 1.1.10 Asegúrese de  que se recopilen los eventos de modificación de permisos de control de acceso discrecional – Level 2 / 1.1.11 Asegúrese de que se recopilen intentos de acceso a archivos no autorizados sin éxito – Level 2 / 1.1.12 Asegúrese de que se recopilan los eventos que modifican la información del usuario / grupo – Level 2 / 1.1.13 Asegúrese de que se recopilan los montajes exitosos del sistema de archivos – Level 2 / 1.1.14 Asegúrese de que se recopile el uso de comandos privilegiados – Level 2 / 1.1.15 Asegúrese de  que los usuarios eliminen los eventos para la eliminación de archivos – Level 2 / 1.1.16 Asegúrese de que se recopile la carga y descarga del módulo del Kernel – Level 2 / 1.1.17 Asegúrese de que se recopilen las acciones del administrador del sistema (sudolog) – Level 2 / 1.1.18 Asegúrese de que la configuración de auditoría sea inmutable – Level 2"
echo "**** $DESCRIPTION"

for OC in $FILES_AUDIT_8
 do
  FILE_A_8=`echo $OC|cut -d":" -f2`
  if [ -f "$FILE_A_8" ]
   then
    echo "###### $FILE_A_8"
    cat $FILE_A_8
   else
    echo "##### $FILE_A_8 NO_EXISTE"
   fi
done
}


verif_crypto_8() {
DESCRIPTION="Verificando 1.10 Ensure system-wide crypto policy is not legacy / 1.11 Ensure system-wide crypto policy is FUTURE or FIPS"
echo "**** $DESCRIPTION"

/usr/bin/grep -i -E '^[[:space:]]*LEGACY[[:space:]]*([[:space:]]+#.*)?$' /etc/crypto-policies/config | /usr/bin/awk '{print} END {if (NR==0) print "pass" ; else print "fail"}'
/usr/bin/grep -i -E '^[[:space:]]*(FUTURE|FIPS)[[:space:]]*([[:space:]]+#.*)?$' /etc/crypto-policies/config
}


impl_crypto_8() {
DESCRIPTION="Verificando 1.10 Ensure system-wide crypto policy is not legacy / 1.11 Ensure system-wide crypto policy is FUTURE or FIPS"
echo "**** $DESCRIPTION"

CHK=`/usr/bin/grep -i -E '^[[:space:]]*(FUTURE|FIPS)[[:space:]]*([[:space:]]+#.*)?$' /etc/crypto-policies/config`
if [ "$CHK" != "FIPS" -o "$CHK" != "FUTURE" ]
 then
   #fips-mode-setup --enable
   #Se cambio a LEGACY porque no deja entrar con las key dss desde BASTION
   update-crypto-policies --set LEGACY
 else
   echo "FIPS OK"
fi
}

verif_rsyslog() {
DESCRIPTION="Verificando: 4.2.1.1 Asegúrese de que el servicio rsyslog esté habilitado – Level 1 /  4.2.1.3 Asegúrese de que los permisos de archivo predeterminados de rsyslog estén configurados – Level 1 / 4.2.1.4 Asegurarse que rsyslog está configurado para enviar logs a SIEM – Level 1"
echo "**** $DESCRIPTION"

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
DESCRIPTION="4.2.1.1 Asegúrese de que el servicio rsyslog esté habilitado – Level 1 /  4.2.1.3 Asegúrese de que los permisos de archivo predeterminados de rsyslog estén configurados – Level 1 / 4.2.1.4 Asegurarse que rsyslog está configurado para enviar logs a SIEM – Level 1"
echo "**** $DESCRIPTION"

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
    echo "\$ModLoad imtcp" >>/tmp/rsyslogd.conf.tmp
    echo "\$InputTCPServerRun 514" >>/tmp/rsyslogd.conf.tmp
    echo "\$FileCreateMode 0640"  >>/tmp/rsyslogd.conf.tmp
    echo "# SOX Modificacion envio a server remoto" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionQueueType LinkedList   # run asynchronously" >>/tmp/rsyslogd.conf.tmp
    echo "\$ActionResumeRetryCount -1    # infinite retries if host is down" >>/tmp/rsyslogd.conf.tmp
    echo "$SIEM_SERVER" >>/tmp/rsyslogd.conf.tmp
    cp -f /tmp/rsyslogd.conf.tmp $FILE_RSYSLOGD
  else
    echo "$SIEM_SERVER ESTA CONFIGURADO EN $FILE_RSYSLOGD"
    grep -vE '^*.*[^I][^I]*@@|^\$ActionQueueType LinkedList|^\$ActionResumeRetryCount -1' $FILE_RSYSLOGD >/tmp/rsyslogd.conf.tmp
    #### MODIFICADO PORQUE ALGUNOS NO LOGEAN LOCALMENTE DESPUES DE LA MODIF
    echo "\$ModLoad imtcp" >>/tmp/rsyslogd.conf.tmp
    echo "\$InputTCPServerRun 514" >>/tmp/rsyslogd.conf.tmp
    echo "\$FileCreateMode 0640"  >>/tmp/rsyslogd.conf.tmp
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


impl_aide() {
DESCRIPTION="Modificando 1.4.1   Asegúrese de que AIDE esté instalado / 1.3.2 Asegurese de que la integridad del sistema de archivos se verifique regularmente - Level 1"
echo "**** $DESCRIPTION"

AIDE_CHK=`rpm -qa|grep aide`

if [ "$AIDE_CHK" == "" ]
 then
  if [ "$DISTRIB" == "RHEL" ]
   then
   wget --user admin --password ibm00ibm  http://apsatellitep03/pub/katello-ca-consumer-latest.noarch.rpm
   rpm -ivh --nodigest --nofiledigest katello-ca-consumer-latest.noarch.rpm
   subscription-manager register --org="MOVISTAR" --activationkey="PREMIUM"
   YUM_CHK=`yum -y install aide >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
   echo "Instalando AIDE $YUM_CHK "
   else
   if [ "$DISTRIB" == "SUSE" ]
   then
    YUM_CHK=`zypper install aide >/dev/null 2>&1 && echo "OK" || echo "ERROR"`
    echo "ESTOY EN SUSE"
   fi
  fi
  else
   echo "AIDE INSTALADO"
   YUM_CHK="OK"
fi

if [ "$YUM_CHK" == "OK" ]
 then
  if [ "$DISTRIB" == "SUSE" ]
   then
    aide --init && mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 
   else
    aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    cp ./config/aidecheck.service /etc/systemd/system/aidecheck.service
    cp ./config/aidecheck.timer /etc/systemd/system/aidecheck.timer
    chmod 0644 /etc/systemd/system/aidecheck.*
    systemctl reenable aidecheck.timer
    systemctl restart aidecheck.timer
    systemctl daemon-reload
  fi
fi  
if [ "$DISTRIB" == "SUSE" ]
 then
  CHK_CRON=`grep "/usr/bin/aide --config" /var/spool/cron/root >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
 else
  CHK_CRON=`grep "/usr/sbin/aide --check" /var/spool/cron/root >/dev/null 2>&1 && echo "OK" ||echo "ERROR"`
fi
echo "$DISTRIB ACAAA"

if [ "$CHK_CRON" == "ERROR" ]
 then
   if [ "$DISTRIB" == "SUSE" ]
    then
     echo "0 5 * * * /usr/bin/aide --config /etc/aide.conf --check" >>/var/spool/cron/tabs/root
dLoad imtcp
   else
     echo "0 5 * * * /usr/sbin/aide --check" >>/var/spool/cron/root
   fi
else
 echo "INFO: AIDE se encuentra configurado en CRON"
fi
}

impl_gdm_suse() {
DESCRIPTION="1.7.2 Asegúrese de que el banner de inicio de sesión GDM esté configurado – Level 1"
echo "$DESCRIPTION"
if [ ! -f /etc/dconf/profile/gdm ]
 then
  echo "user-db:user" >/etc/dconf/profile/gdm
  echo "system-db:gdm" >>/etc/dconf/profile/gdm
  echo "file-db:/usr/share/gdm/greeter-dconf-defaults" >>/etc/dconf/profile/gdm
  mkdir -p /etc/dconf/db/gdm.d
  echo "[org/gnome/login-screen]" >/etc/dconf/db/gdm.d/01-banner-message
  echo "banner-message-enable=true" >>/etc/dconf/db/gdm.d/01-banner-message
  echo "banner-message-text=\"Todo uso no autorizado o divulgacion de la informacion de este sistema dara lugar a las medidas legales que correspondan. Las actividades en este sistema estan auditadas y monitoreadas.\"" >>/etc/dconf/db/gdm.d/01-banner-message
  echo "[org/gnome/login-screen]" >/etc/dconf/db/gdm.d/00-login-screen
  echo "disable-user-list=true" >>/etc/dconf/db/gdm.d/00-login-screen
  dconf update
fi
}


impl_fs_suse() {
case ${DISTRIB} in
  SUSE) FILESYS_GRAL_OPTS="${FILESYS_SUSE_OPTS}";;
  CentOS) FILESYS_GRAL_OPTS="${FILESYS_CENTOS_OPTS}";;
esac

 echo ${FILESYS_GRAL_OPTS}|tr "|" "\n"|tr "#" " "|while read FS FSOPTS
  do
   echo $FSOPTS|tr "," "\n"|while read OPTS
    do
    CHKFS=`grep $FS ${FSTAB}|grep $OPTS >/dev/null 2>&1 && echo "OK" || echo "NO"`
    if [ "$CHKFS" == "NO" ]
     then
      CHFS=`awk -v v=$FS -v o=$OPTS '!/^#/ && ($2 == v) { if(!match(o,$4)) $4=$4","o } 1' < ${FSTAB} > ${FSTAB}.tmp 2>&1 && echo "CH_OK" || echo "NO_SET"`
      mv ${FSTAB}.tmp ${FSTAB}
      echo "$OPTS"
    fi
   done
   echo "$FS  $FSOPTS $CHFS"
   mount -o remount $FS
  done
}

impl_cpassword_suse() {
DESCRIPTION="5.3.1 Asegúrese de que los requisitos de creación de contraseña estén configurados – Level 1"
echo "$DESCRIPTION"

pam-config -a --cracklib-retry=3 --cracklib-minlen=14 --cracklib-dcredit=-1 --cracklib-ucredit=-1 --cracklib-ocredit=-1 --cracklib-lcredit=-1
pam-config -a --pwhistory  --pwhistory-remember=5 --unix-sha512
}

impl_chage() {
for USER in cconfsoc gestkeyh segdatos usaddm tfaipat1 beasvc oracle ctmagent doxadm doxdba doxesb doxinfra doxmig doxods doxops gesinc ibmbas ibmbkp ibmdb2 ibmdba ibmimple ibmmid ibmoper ibmsop ibmstg ibmunx ibmweb segabm segunix tgtarq tgtn2be tgtn2fe
do
 chage -M -1 ${USER}
 chage -E -1 ${USER}
done
}

impl_borra_shadow_group_rhel8() {
#Borra un grupo que se crea por error en la plantilla de build
sed -i '/^shadow:x:15:/d' /etc/group
}

impl_sshd_centos_6() {
SSH_PARAM="Protocol 2|LogLevel INFO|MaxAuthTries 4|IgnoreRhosts yes|HostbasedAuthentication no|PermitRootLogin yes|PermitEmptyPasswords no|PermitUserEnvironment no|ClientAliveInterval 1800|ClientAliveCountMax 0|Banner /etc/issue.net|X11Forwarding no|Match address 10.204.167.185,10.204.164.159,10.206.19.47,10.166.13.238,10.166.13.254,10.166.31.102|LoginGraceTime 60|UsePAM yes|AllowTcpForwarding no|maxstartups 10:30:60|MaxSessions 4|Ciphers aes128-ctr,aes192-ctr,aes256-ctr|MACs hmac-sha1,umac-64@openssh.com"
impl_ssh
}

template_centos_password_auth_6() {
echo "#%PAM-1.0"
echo "# This file is auto-generated."
echo "# User changes will be destroyed the next time authconfig is run."

echo "auth        required      pam_env.so"
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900"
echo "auth        [success=1 default=bad]    pam_unix.so nullok try_first_pass"
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"
echo "auth        requisite     pam_succeed_if.so uid >= 500 quiet"
echo "auth        required      pam_deny.so"
echo ""
echo "account     required      pam_unix.so"
echo "account     sufficient    pam_localuser.so"
echo "account     sufficient    pam_succeed_if.so uid < 500 quiet"
echo "account     required      pam_permit.so"
echo ""
echo "password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-2 ucredit=-1 ocredit=-1 lcredit=-1"
echo "password required pam_pwhistory.so remember=5"
echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok"
echo "password    required      pam_deny.so"
echo ""
echo "session     optional      pam_keyinit.so revoke"
echo "session     required      pam_limits.so"
echo "session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid"
echo "session     required      pam_unix.so"
}


template_centos_system_auth_6() {
echo "#%PAM-1.0"
echo "# This file is auto-generated."
echo "# User changes will be destroyed the next time authconfig is run."
echo "auth        required      pam_env.so"
echo "auth required pam_faillock.so preauth audit silent deny=5 unlock_time=900"
echo "auth        [success=1 default=bad]    pam_unix.so nullok try_first_pass"
echo "auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=900"
echo "auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=900"
echo "auth        requisite     pam_succeed_if.so uid >= 500 quiet"
echo "auth        required      pam_deny.so"
echo ""
echo "account     required      pam_unix.so"
echo "account     sufficient    pam_localuser.so"
echo "account     sufficient    pam_succeed_if.so uid < 500 quiet"
echo "account     required      pam_permit.so"
echo ""
echo "password    requisite     pam_cracklib.so try_first_pass retry=3 minlen=14 dcredit=-2 ucredit=-1 ocredit=-1 lcredit=-1"
echo "password required pam_pwhistory.so remember=5"
echo "password    sufficient    pam_unix.so sha512 shadow nullok try_first_pass use_authtok"
echo "password    required      pam_deny.so"
echo ""
echo "session     optional      pam_keyinit.so revoke"
echo "session     required      pam_limits.so"
echo "session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid"
echo "session     required      pam_unix.so"
}

impl_varios_centos_6() {
echo "1.1.22   Deshabilitar automontado – Level 1"
chkconfig autofs off
echo "1.5.4 Ensure prelink is disabled"
prelink -ua
yum -y remove prelink
echo "1.2.3   Asegúrese de que gpgcheck esté activado. – Level 1"

echo "4.1.3 Ensure auditing for processes that start prior to auditd is enabled"
sed -i '/kernel \/vmlinuz/ s/$/ audit=1/' $FILE_GRUB

echo "AUDITORIA"
CENTOS_VAR="-w /var/log/lastlog -p wa -k logins|-w /var/run/faillock/ -p wa -k logins|-w /etc/sysconfig/network -p wa -k system-locale|-w /etc/sysconfig/network-scripts/ -p wa -k system-locale"
echo "# This file contains the auditctl rules that are loaded" >$FILE_AUDIT_RULES
echo "# whenever the audit daemon is started via the initscripts." >>$FILE_AUDIT_RULES
echo "# The rules are simply the parameters that would be passed" >>$FILE_AUDIT_RULES
echo "# to auditctl." >>$FILE_AUDIT_RULES
echo "" >>$FILE_AUDIT_RULES
echo "# First rule - delete all" >>$FILE_AUDIT_RULES
echo "-D" >>$FILE_AUDIT_RULES
echo "" >>$FILE_AUDIT_RULES
echo "# Increase the buffers to survive stress events." >>$FILE_AUDIT_RULES
echo "# Make this bigger for busy systems" >>$FILE_AUDIT_RULES
echo "-b 320" >>$FILE_AUDIT_RULES
echo "" >>$FILE_AUDIT_RULES
echo "# Feel free to add below this line. See auditctl man page" >>$FILE_AUDIT_RULES
echo "$VAR_SCOPE"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_AUDIT"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_LOGINS"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_TIME" |tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_MAC"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$CENTOS_VAR"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_LOCALE"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_PERM"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_ACCESS"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_IDENTITY"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_MOUNTS"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_DELETE"|tr "|" "\n" >>$FILE_AUDIT_RULES
echo "$VAR_MODULES"|tr "|" "\n" >>$FILE_AUDIT_RULES
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged" }' >>$FILE_AUDIT_RULES
echo "$VAR_FINAL"|tr "|" "\n" >>$FILE_AUDIT_RULES

echo "PAM...."
cp $FILE_PASS_AUTH ${FILE_PASS_AUTH}.SOX
cp $FILE_SYS_AUTH ${FILE_SYS_AUTH}.SOX
template_centos_password_auth_6 >${FILE_PASS_AUTH}-ac
template_centos_system_auth_6 >${FILE_SYS_AUTH}-ac
sed -i "/pam_wheel.so use_uid/s/^#//g" /etc/pam.d/su
chown root:root /etc/gshadow-
chmod 000 /etc/gshadow-
}

common_part() {
echo "esta es la parte comun"
backup_action backup
ver_dis_fs_prot
impl_spkey 
impl_ibmunx 
impl_dis_fs 
if [ "$DISTRIB" == "SUSE" -o  "$DISTRIB" == "CentOS" ]
then
 impl_fs_suse
else
 impl_fs 
fi
impl_automount 
impl_gpgcheck 
impl_limits 
impl_sysctl 
impl_banner 
impl_update 
impl_ntp 
impl_remove_pkg 
impl_find 
impl_rsyslog
impl_wireless
impl_audit
impl_audit_rules
impl_net
impl_postfix
impl_selinux
impl_services
impl_shadow
impl_sudo
impl_sudo_opts
change_dir_perms
impl_cron 
if [ "$DISTRIB" != "CentOS" ]
then
impl_ssh
fi
impl_chage
}

ubuntu_part() {
echo "Esto es Unubuntu"
}

redhat_5_6_7() {
impl_cripto
impl_pass
}

rhel8_part() {
echo "Esto es Redhat 8"
impl_aide
impl_audit_8
impl_authselect
impl_crypto_8
impl_firewall
impl_grub2
impl_grub2_cfg
impl_grub2_passwd
impl_grub2_uniq
impl_journal
impl_audit
impl_borra_shadow_group_rhel8
}

suse_part() {
echo "Esto es SUSE"
impl_cpassword_suse
impl_pam_suse
impl_grub2_cfg
impl_journal
impl_audit_8
impl_gdm_suse
impl_aide
impl_services
impl_remove_pkg
impl_gpgcheck_suse
}

centos_part() {
echo "Esto es CENTOS"
if [ "$VER" == "6" ]
 then
  echo "Esto es Centos 6"
  impl_sshd_centos_6
  impl_varios_centos_6
 else
  echo "Esto es Centos > 7"
fi
}

test_module() {
echo "testea algun modulo"
MODULO=$1
echo "$MODULO"
$MODULO
}


implementa() {
case $DISTRIB in
   Ubuntu) common_part; ununtu_part;;
   RHEL) common_part; rhel8_part;;
   SUSE) common_part; suse_part;;
   CentOS) common_part; centos_part;;
esac
}





help() {
 VERSIONS="SOX script V $SCRIPTVER"
 echo "$VERSIONS Certificado en SUSE12 SUSE15 RHEL5 RHEL6 RHEL7 RHEL8 Centos6 Centos7 Ubuntu"
 echo "$0 [ -v|-i|-restore|-h]"
 echo " -v : verifica antes de implementar"
 echo " -i : implementa y hace backup"
 echo " -sap : implementa y hace backup con el apartado de SUSE de SAP"
 echo " -restore : recupera de un backup"
 echo " -test : testea un modulo"
 echo " -list : lista modulos"
 echo " -h : este help"
}

ID=`id|awk '{print $1}'|grep "root" >/dev/null && echo "root" || echo "NO_OK"`

if [ "$ID" != "root" ]
then
  echo "$0 Solo puede ser ejecutado como root"
else
lnx_ver
common_param
fi


case $OPTION in
    -v ) verif ;;
    -restore ) backup_action restore;;
    -i ) implementa ;;
    -sap ) SAP=1;implementa ;;
    -test ) test_module $MODULE;;
    -list ) lista_modulos;;
    -h | * ) help ;;
esac

