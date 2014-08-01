#!/bin/bash
#====================================================================#
#  MagenX - Automated Deployment of Virtual Mail Server              #
#  Copyright (C) 2013 admin@magentomod.com                           #
#  All rights reserved.                                              #
#====================================================================#

ADOVMS_VER="3.0.10-1"

# Simple colors
RED="\e[31;40m"
GREEN="\e[32;40m"
YELLOW="\e[33;40m"
WHITE="\e[37;40m"
BLUE="\e[0;34m"

# Background
DGREYBG="\t\t\e[100m"
BLUEBG="\e[44m"
REDBG="\t\t\e[41m"

# Styles
BOLD="\e[1m"

# Reset
RESET="\e[0m"

# quick-n-dirty coloring
function WHITETXT() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "\t\t${WHITE}${BOLD}${MESSAGE}${RESET}"
}
function BLUETXT() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "\t\t${BLUE}${BOLD}${MESSAGE}${RESET}"
}
function REDTXT() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "\t\t${RED}${BOLD}${MESSAGE}${RESET}"
} 
function GREENTXT() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "\t\t${GREEN}${BOLD}${MESSAGE}${RESET}"
}
function YELLOWTXT() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "\t\t${YELLOW}${BOLD}${MESSAGE}${RESET}"
}
function BLUEBG() {
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "${BLUEBG}${MESSAGE}${RESET}"
}
function pause() {
   read -p "$*"
}

clear
###################################################################################
#                                     START CHECKS                                #
###################################################################################
echo

# root?
if [[ ${EUID} -ne 0 ]]; then
  echo
  REDTXT "ERROR: THIS SCRIPT MUST BE RUN AS ROOT!"
  YELLOWTXT "------> USE SUPER-USER PRIVILEGES."
  exit 1
  else
  GREENTXT "PASS: ROOT!"
fi

# do we have CentOS 6?
if grep -q "CentOS release 6" /etc/redhat-release > /dev/null 2>&1 ; then
  GREENTXT "PASS: CENTOS RELEASE 6"
  else
  echo
  REDTXT "ERROR: UNABLE TO DETERMINE DISTRIBUTION TYPE."
  YELLOWTXT "------> THIS CONFIGURATION FOR CENTOS 6."
  echo
  exit 1
fi

# check if x64.
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  GREENTXT "PASS: YOUR ARCHITECTURE IS 64-BIT"
  else
  echo
  REDTXT "ERROR: YOUR ARCHITECTURE IS 32-BIT?"
  YELLOWTXT "------> CONFIGURATION FOR 64-BIT ONLY."
  echo
  exit 1
fi


# network is up?
host1=74.125.24.106
host2=208.80.154.225
RESULT=$(((ping -w3 -c2 ${host1} || ping -w3 -c2 ${host2}) > /dev/null 2>&1) && echo "up" || (echo "down" && exit 1))
if [[ ${RESULT} == up ]]; then
  GREENTXT "PASS: NETWORK IS UP. GREAT, LETS START!"
  else
  REDTXT "ERROR: NETWORK IS DOWN?"
  YELLOWTXT "------> PLEASE CHECK YOUR NETWORK SETTINGS."
  echo
  echo
  exit 1
fi

# we need php > 5.4.x
PHPVER=$(php -r \@phpinfo\(\)\; | grep 'PHP Version' -m 1 | awk {'print $4'} | cut -d'.' -f 2)
if [ ${PHPVER} = 4 ] || [ ${PHPVER} > 4 ]; then
  GREENTXT "PASS: YOUR PHP IS ${WHITE}${BOLD}$(php -r \@phpinfo\(\)\; | grep 'PHP Version' -m 1 | awk {'print $4'})"
  else
  echo
  REDTXT "ERROR: YOUR PHP VERSION IS NOT > 5.4"
  YELLOWTXT "------> CONFIGURATION FOR PHP > 5.4 ONLY."
  echo
  exit 1
fi
echo
echo
###################################################################################
#                                     CHECKS END                                  #
###################################################################################
echo
if grep -q "yes" ~/adovms/.terms >/dev/null 2>&1 ; then
echo "...... loading menu"
sleep 1
      else
        YELLOWTXT "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo
        YELLOWTXT "BY INSTALLING THIS SOFTWARE AND BY USING ANY AND ALL SOFTWARE"
        YELLOWTXT "YOU ACKNOWLEDGE AND AGREE:"
            echo
        YELLOWTXT "THIS SOFTWARE AND ALL SOFTWARE PROVIDED IS PROVIDED AS IS"
        YELLOWTXT "UNSUPPORTED AND WE ARE NOT RESPONSIBLE FOR ANY DAMAGE"
            echo
        YELLOWTXT "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
            echo
            echo
	echo -n "---> Do you agree to these terms?  [y/n][y]:"
 	read terms_agree
        if [ "$terms_agree" == "y" ];then
          echo
            mkdir -p ~/adovms
            echo "yes" > ~/adovms/.terms
            else
            echo "Exiting"
           exit 1
          echo
        fi
fi
###################################################################################
#                                  HEADER MENU START                              #
###################################################################################

showMenu () {
printf "\033c"
        echo
        echo
        echo -e "${DGREYBG}${BOLD}  Virtual Mail Server Configuration v.$ADOVMS_VER  ${RESET}"
        echo -e "\t\t${BLUE}${BOLD}:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::  ${RESET}"
        echo
        echo -e "\t\t${WHITE}${BOLD}-> For repositories installation enter :  ${YELLOW} repo  ${RESET}"
        echo -e "\t\t${WHITE}${BOLD}-> For packages installation enter     :  ${YELLOW} packages  ${RESET}"
        echo -e "\t\t${WHITE}${BOLD}-> Download and install vimbadmin      :  ${YELLOW} vimbadmin  ${RESET}"
        echo -e "\t\t${WHITE}${BOLD}-> Download and install roundcube      :  ${YELLOW} roundcube  ${RESET}"
        echo -e "\t\t${WHITE}${BOLD}-> Setup and configure everything      :  ${YELLOW} config  ${RESET}"
        echo
        echo -e "\t\t${BLUE}${BOLD}:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::  ${RESET}"
        echo
        echo -e "\t\t${WHITE}${BOLD}-> To quit enter                       :  ${RED} exit  ${RESET}"
        echo
        echo
}
while [ 1 ]
do
        showMenu
        read CHOICE
        case "$CHOICE" in
                "repo")
echo
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " NOW BEGIN REPOSITORIES INSTALLATION "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
WHITETXT "============================================================================="
echo
echo -n "---> Start EPEL repository installation? [y/n][n]:"
read repoE_install
if [ "$repoE_install" == "y" ];then
   echo
     GREENTXT "Running Installation of Extra Packages for Enterprise Linux"
     echo
     rpm  --quiet -q epel-release
  if [ "$?" = 0 ]
    then
      GREENTXT "ALREADY INSTALLED"
       else
       rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
  fi
     else
     YELLOWTXT "EPEL repository installation skipped. Next step"
fi
echo
WHITETXT "============================================================================="
echo
echo -n "---> Start ATrpms Testing Repository installation? [y/n][n]:"
read repoC_install
if [ "$repoC_install" == "y" ];then
   echo
     GREENTXT "Running Installation of ATrpms Testing repository"
     echo
     rpm  --quiet -q atrpms-repo
  if [ "$?" = 0 ]
    then
      GREENTXT "ALREADY INSTALLED"
      else
      rpm -Uvh http://dl.atrpms.net/el6-x86_64/atrpms/stable/atrpms-repo-6-7.el6.x86_64.rpm
  fi
     echo
     else
     YELLOWTXT "ATrpms Testing repository installation skipped. Next step"
fi
echo
WHITETXT "============================================================================="
echo
echo -n "---> Start Repoforge repository installation? [y/n][n]:"
read repoF_install
if [ "$repoF_install" == "y" ];then
   echo
     GREENTXT "Running Installation of Repoforge"
     echo
     rpm  --quiet -q rpmforge-release
  if [ "$?" = 0 ]
    then
      GREENTXT "ALREADY INSTALLED"
      else
      rpm -Uvh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.2-2.el6.rf.x86_64.rpm
  fi
    echo
    else
    YELLOWTXT "Repoforge installation skipped. Next step"
fi
echo 
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " REPOSITORIES INSTALLATION FINISHED "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo
echo
pause "---> Press [Enter] key to show menu"
printf "\033c"
;;
"packages")
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " NOW INSTALLING POSTFIX, DOVECOT, CLAMAV, OPENDKIM "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo
echo -n "---> Start mail packages installation? [y/n][n]:"
read mail_install
if [ "$mail_install" == "y" ];then
		echo
    GREENTXT "Running mail packages installation"
		echo
        yum --enablerepo=atrpms-testing -y install dovecot dovecot-pigeonhole 
		echo
    GREENTXT "Running opendkim installation"
		echo
		yum --enablerepo=epel-testing -y install opendkim git subversion
		echo
    GREENTXT "Running ClamAV antivirus scanner installation"
		echo
		yum --disablerepo=rpmforge,atrpms -y install clamsmtp clamd clamav
		echo
    GREENTXT "Get the latest postfix (temporary solution)"
		echo
                rpm -e --nodeps postfix
		rpm -ihv http://repos.oostergo.net/6/postfix-2.11/postfix-2.11.1-1.el6.x86_64.rpm
		echo
                rpm  --quiet -q postfix dovecot dovecot-pigeonhole opendkim git subversion
    if [ $? = 0 ]
      then
        echo
        GREENTXT "INSTALLED"
        else
        REDTXT "ERROR"
        exit
    fi
	    echo
		chkconfig postfix on
		chkconfig dovecot on
		chkconfig opendkim on
		chkconfig clamsmtpd on
		chkconfig clamav on
		alternatives --set mta /usr/sbin/sendmail.postfix
	

cat > /etc/init.d/clamsmtpd <<END
#!/bin/sh
# clamsmtpd     Script to start/stop clamsmtpd.
#
# chkconfig:    - 63 38
# description:  clamsmtpd is smtpd for clamav antivirus daemon.
#
# processname:  clamsmtpd
# pidfile:      /var/run/clamd.clamsmtp/clamsmtpd.pid
#
# author: Martynas Bieliauskas <martynas@inet.lt> 2004 Sep 20
# author: Nathanael D. Noblet <nathanael@gnat.ca> 2010 Jan 18
#

# Source function library
. /etc/rc.d/init.d/functions

# Get network config
. /etc/sysconfig/network

# Source config
if [ -f /etc/sysconfig/clamsmtpd ] ; then
    . /etc/sysconfig/clamsmtpd
else
    CONFIG_FILE=/etc/clamsmtpd.conf
    PID_DIR=/var/run/clamd.clamsmtp
fi

RETVAL=0

start() {
        echo -n \$"Starting ClamSmtpd: "
        daemon /usr/sbin/clamsmtpd -f \$CONFIG_FILE -p \$PID_DIR/clamsmtpd.pid
        RETVAL=$?
        echo
        [ \$RETVAL -eq 0 ] && touch /var/lock/subsys/clamsmtpd
        return \$RETVAL
}

stop() {
        echo -n $"Stopping ClamSmtpd: "
        killproc clamsmtpd
        RETVAL=\$?
        echo
        [ \$RETVAL -eq 0 ] && rm -f /var/run/\$PID_DIR/clamsmtpd.pid /var/lock/subsys/clamsmtpd
        return \$RETVAL
}

restart() {
        stop
        start
}

case "\$1" in
  start)
        start
        ;;
  stop)
        stop
        ;;
  status)
      status clamsmtpd
        ;;
  restart)
        restart
        ;;
  condrestart)
        [ -f /var/lock/subsys/clamsmtpd ] && restart || :
        ;;
*)
        echo \$"Usage: \$0 {start|stop|status|restart}"
        exit 1

esac
exit \$?
END
        else
        YELLOWTXT "Mail packages installation skipped. Next step"
fi
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " FINISHED PACKAGES INSTALLATION "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"vimbadmin")
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " NOW DOWNLOADING ViMbAdmin "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo -n "---> Download and configure ViMbAdmin 3? [y/n][n]:"
read vmb_down
if [ "$vmb_down" == "y" ];then
     read -e -p "---> Edit your installation folder full path: " -i "/var/www/html/vmb" VMB_PATH
	 echo
        echo "  ViMbAdmin will be installed into:" 
		GREENTXT ${VMB_PATH}
		echo
		pause '------> Press [Enter] key to continue'
		echo
		mkdir -p ${VMB_PATH} && cd $_
		echo
		###################################################
		git config --global url."https://".insteadOf git://
		###################################################
        git clone git://github.com/opensolutions/ViMbAdmin.git .
		echo
		wget -O composer.json https://raw.githubusercontent.com/magenx/ADOVMS-M/master/composer.json
		echo
		echo "  Installing Third Party Libraries"
		echo
        cd ${VMB_PATH}
		echo "  Get composer"
		curl -sS https://getcomposer.org/installer | php
		mv composer.phar composer
		echo
        ./composer install
		cp ${VMB_PATH}/public/.htaccess.dist ${VMB_PATH}/public/.htaccess
echo
cat > /root/adovms/.adovms_index <<END
mail	$VMB_PATH
END
	fi
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " FINISHED ViMbAdmin INSTALLATION "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"roundcube")
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " NOW DOWNLOADING ROUNDCUBE "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
echo -n "---> Download and configure ROUNDCUBE 1.x? [y/n][n]:"
read rcb_down
if [ "$rcb_down" == "y" ];then
     read -e -p "---> Edit your installation folder full path: " -i "/var/www/html/rcb" RCB_PATH
	 echo
        echo "  ROUNDCUBE will be installed into:" 
		GREENTXT ${RCB_PATH}
		echo
		pause '------> Press [Enter] key to continue'
		echo
		mkdir -p ${RCB_PATH}
        cd ${RCB_PATH}
		echo
		wget -qO - http://downloads.sourceforge.net/project/roundcubemail/roundcubemail/1.0.2/roundcubemail-1.0.2.tar.gz | tar -xz --strip 1
		echo
		ls -l ${RCB_PATH}
		echo
		GREENTXT "INSTALLED"
	echo	
	echo	
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " FINISHED ROUNDCUBE INSTALLATION "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
  else
        YELLOWTXT "ROUNDCUBE installation skipped. Next step"
fi
echo
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"config")
echo
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
BLUEBG " NOW CONFIGURING POSTFIX, DOVECOT, OPENDKIM, ViMbAdmin AND ROUNDCUBE "
echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
echo
printf "\033c"
echo
WHITETXT "Creating virtual mail User and Group"
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /home/vmail -m -s /sbin/nologin
echo
WHITETXT "Creating ViMbAdmin MySQL DATABASE and USER"
echo
echo -n "---> Generate ViMbAdmin strong password? [y/n][n]:"
read vmb_pass_gen
if [ "$vmb_pass_gen" == "y" ];then
   echo
     VMB_PASSGEN=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1)
     WHITETXT "ViMbAdmin database password: ${RED} ${VMB_PASSGEN}"
     YELLOWTXT "!REMEMBER IT AND KEEP IT SAFE!"
fi
echo
echo
read -p "---> Enter MySQL ROOT password : " MYSQL_ROOT_PASS
read -p "---> Enter ViMbAdmin database host : " VMB_DB_HOST
read -p "---> Enter ViMbAdmin database name : " VMB_DB_NAME
read -p "---> Enter ViMbAdmin database user : " VMB_DB_USER_NAME
echo
mysql -u root -p${MYSQL_ROOT_PASS} <<EOMYSQL
CREATE USER '$VMB_DB_USER_NAME'@'$VMB_DB_HOST' IDENTIFIED BY '$VMB_PASSGEN';
CREATE DATABASE $VMB_DB_NAME;
GRANT ALL PRIVILEGES ON $VMB_DB_NAME.* TO '$VMB_DB_USER_NAME'@'$VMB_DB_HOST' WITH GRANT OPTION;
FLUSH PRIVILEGES;
exit
EOMYSQL
echo
echo
echo -n "---> SETUP ROUNDCUBE MySQL DATABASE AND USER 1.x? [y/n][n]:"
read rcb_sdb
if [ "$rcb_sdb" == "y" ];then
echo
WHITETXT "CREATING ROUNDCUBE MySQL DATABASE AND USER"
echo
echo -n "---> Generate ROUNDCUBE strong password? [y/n][n]:"
read rcb_pass_gen
if [ "$rcb_pass_gen" == "y" ];then
   echo
     RCB_PASSGEN=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1)
     WHITETXT "ROUNDCUBE database password: ${RED} ${RCB_PASSGEN}"
     YELLOWTXT "!REMEMBER IT AND KEEP IT SAFE!"
fi
echo
echo
read -p "---> Enter MySQL ROOT password : " MYSQL_ROOT_PASS
read -p "---> Enter ROUNDCUBE database host : " RCB_DB_HOST
read -p "---> Enter ROUNDCUBE database name : " RCB_DB_NAME
read -p "---> Enter ROUNDCUBE database user : " RCB_DB_USER_NAME
echo
mysql -u root -p${MYSQL_ROOT_PASS} <<EOMYSQL
CREATE USER '$RCB_DB_USER_NAME'@'$RCB_DB_HOST' IDENTIFIED BY '$RCB_PASSGEN';
CREATE DATABASE $RCB_DB_NAME /*!40101 CHARACTER SET utf8 COLLATE utf8_general_ci */;
GRANT ALL PRIVILEGES ON $RCB_DB_NAME.* TO '$RCB_DB_USER_NAME'@'$RCB_DB_HOST' WITH GRANT OPTION;
FLUSH PRIVILEGES;
exit
EOMYSQL
echo
WHITETXT "Import Roundcube database tables..."
mysql -u root -p${MYSQL_ROOT_PASS} ${RCB_DB_NAME} < ${RCB_PATH}/SQL/mysql.initial.sql
  else
  YELLOWTXT "ROUNDCUBE installation skipped. Next step"
fi
echo
WHITETXT "============================================================================="
echo
echo -n "---> Load preconfigured postfix dovecot configs? [y/n][n]:"
read load_configs
if [ "$load_configs" == "y" ];then
echo
REDTXT "YOU HAVE TO CHECK THEM AFTER ANYWAY"
echo
mkdir -p /etc/postfix/mysql
mkdir -p /etc/postfix/config
WHITETXT "Writing Postfix/ViMbAdmin mysql connection files"
cat > /etc/postfix/mysql/virtual-alias-maps.cf <<END
user = $VMB_DB_USER_NAME
password = $VMB_PASSGEN
hosts = $VMB_DB_HOST
dbname = $VMB_DB_NAME
query = SELECT goto FROM alias WHERE address = '%s' AND active = '1'
END
cat > /etc/postfix/mysql/virtual-mailbox-domains.cf <<END
user = $VMB_DB_USER_NAME
password = $VMB_PASSGEN
hosts = $VMB_DB_HOST
dbname = $VMB_DB_NAME
query = SELECT domain FROM domain WHERE domain = '%s' AND backupmx = '0' AND active = '1'
END
cat > /etc/postfix/mysql/virtual-mailbox-maps.cf <<END
user = $VMB_DB_USER_NAME
password = $VMB_PASSGEN
hosts = $VMB_DB_HOST
dbname = $VMB_DB_NAME
query = SELECT maildir FROM mailbox WHERE username = '%s' AND active = '1'
END
echo
WHITETXT "Writing Postfix main.cf file"
read -p "---> Enter your domain : " VMB_DOMAIN
read -p "---> Enter your hostname : " VMB_MYHOSTNAME
read -p "---> Enter your admin email : " VMB_ADMIN_MAIL
read -e -p "---> Enter your ssl cert location: " -i "/etc/ssl/domain.crt"  VMB_SSL_CRT
read -e -p "---> Enter your ssl key location: " -i "/etc/ssl/server.key"  VMB_SSL_KEY
cat > /etc/postfix/main.cf <<END
smtpd_banner = \$myhostname ESMTP Goofy

#specify 0 when mail delivery should be tried only once.
#maximal_queue_lifetime = 0

queue_run_delay = 1h
minimal_backoff_time = 1h
maximal_queue_lifetime = 3h
maximal_backoff_time = 3h
bounce_queue_lifetime = 3h


biff = no
append_dot_mydomain = no
inet_interfaces = all
dovecot_destination_recipient_limit = 1

disable_vrfy_command = yes
broken_sasl_auth_clients = no

additional_config_dir = /etc/postfix/config

smtpd_forbidden_commands = CONNECT GET POST
smtpd_tls_cert_file = $VMB_SSL_CRT
smtpd_tls_key_file = $VMB_SSL_KEY
smtpd_tls_auth_only = yes
smtpd_tls_security_level = may
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_helo_required = yes
smtpd_reject_unlisted_sender = yes
smtpd_reject_unlisted_recipient = yes
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache

smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtp_tls_security_level = may
smtp_always_send_ehlo = yes

myhostname = $VMB_MYHOSTNAME
mydomain = $VMB_DOMAIN
mydestination = localhost
mynetworks = 127.0.0.0/8
myorigin = \$mydomain

mailbox_size_limit = 0

virtual_mailbox_domains = mysql:/etc/postfix/mysql/virtual-mailbox-domains.cf
virtual_mailbox_maps = mysql:/etc/postfix/mysql/virtual-mailbox-maps.cf
virtual_alias_maps = mysql:/etc/postfix/mysql/virtual-alias-maps.cf
virtual_uid_maps = static:5000
virtual_gid_maps = static:5000
virtual_transport = dovecot

smtpd_restriction_classes =
                            verify_sender,
                            rbl_cbl_abuseat_org,
                            rbl_sbl_spamhaus_org,
                            rbl_dul_ru, 
                            rbl_spamcop,
                            white_client_ip,
                            black_client_ip,
                            block_dsl,
                            helo_access,
                            white_client,
                            black_client,
                            mx_access


verify_sender        = reject_unverified_sender, permit
rbl_cbl_abuseat_org  = reject_rbl_client cbl.abuseat.org
rbl_dul_ru           = reject_rbl_client dul.ru
rbl_sbl_spamhaus_org = reject_rbl_client sbl.spamhaus.org
rbl_spamcop          = reject_rbl_client bl.spamcop.net

white_client_ip      = check_client_access pcre:\$additional_config_dir/white_client_ip
black_client_ip      = check_client_access pcre:\$additional_config_dir/black_client_ip
white_client         = check_sender_access pcre:\$additional_config_dir/white_client
black_client         = check_sender_access pcre:\$additional_config_dir/black_client
block_dsl            = regexp:\$additional_config_dir/block_dsl
helo_access          = check_helo_access pcre:\$additional_config_dir/helo_checks
mx_access            = check_sender_mx_access cidr:\$additional_config_dir/mx_access

smtpd_milters           = inet:127.0.0.1:8891
non_smtpd_milters       = \$smtpd_milters
milter_default_action   = quarantine
milter_protocol   = 6

content_filter = scan:127.0.0.1:10025

#notify_classes = bounce, delay, policy, protocol, resource, software
#error_notice_recipient = $VMB_ADMIN_MAIL

smtpd_client_restrictions =
                            white_client_ip,
                            black_client_ip,
                            white_client,
                            black_client,
                            helo_access,
                            block_dsl,
                            rbl_dul_ru,
                            rbl_sbl_spamhaus_org,
                            rbl_spamcop,
                            rbl_cbl_abuseat_org,
                            permit_mynetworks,
                            permit_sasl_authenticated,
                            reject_unauth_destination,
                            reject_unauth_pipelining,
                            reject_unknown_address,
                            reject_unknown_recipient_domain,
                            reject_unknown_sender_domain

smtpd_sender_restrictions =
                            white_client,
                            white_client_ip,
                            black_client_ip,
                            reject_unknown_recipient_domain,
                            reject_unknown_sender_domain,
                            reject_non_fqdn_recipient,
                            reject_non_fqdn_sender,
                            permit_sasl_authenticated,
                            permit_mynetworks,
                            mx_access,
                            reject_unlisted_sender,
                            reject_unauth_destination
				
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination

smtpd_recipient_restrictions = verify_sender
                               white_client,
                               helo_access,
                               reject_unknown_recipient_domain,
                               reject_unknown_sender_domain,
                               reject_non_fqdn_recipient,
                               reject_non_fqdn_sender,
                               reject_unauth_pipelining,
                               permit_sasl_authenticated,
                               permit_mynetworks,
                               reject_unlisted_recipient,
                               reject_unknown_address,
                               reject_unauth_destination,
                               reject_multi_recipient_bounce

smtpd_data_restrictions =
                          reject_unauth_pipelining,
                          reject_multi_recipient_bounce
						  
sample_directory = /usr/share/doc/postfix-2.10.0/samples
sendmail_path = /usr/sbin/sendmail
setgid_group = postdrop
command_directory = /usr/sbin
manpage_directory = /usr/share/man
daemon_directory = /usr/libexec/postfix
newaliases_path = /usr/bin/newaliases
mailq_path = /usr/bin/mailq
queue_directory = /var/spool/postfix
mail_owner = postfix
data_directory = /var/lib/postfix
END

echo
WHITETXT "Writing Postfix master.cf file"
cat > /etc/postfix/master.cf <<END
#
# Postfix master process configuration file.  For details on the format
# of the file, see the master(5) manual page (command: "man 5 master").
#
# Do not forget to execute "postfix reload" after editing this file.
#
# ==========================================================================
# service type  private unpriv  chroot  wakeup  maxproc command + args
#               (yes)   (yes)   (yes)   (never) (100)
# ==========================================================================
smtp      inet  n       -       n       -       -       smtpd
smtps     inet  n       -       n       -       -       smtpd
  -o smtpd_tls_wrappermode=yes
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_client_restrictions=permit_sasl_authenticated,reject
pickup    fifo  n       -       n       60      1       pickup
cleanup   unix  n       -       n       -       0       cleanup
qmgr      fifo  n       -       n       300     1       qmgr
tlsmgr    unix  -       -       n       1000?   1       tlsmgr
rewrite   unix  -       -       n       -       -       trivial-rewrite
bounce    unix  -       -       n       -       0       bounce
defer     unix  -       -       n       -       0       bounce
trace     unix  -       -       n       -       0       bounce
verify    unix  -       -       n       -       1       verify
flush     unix  n       -       n       1000?   0       flush
proxymap  unix  -       -       n       -       -       proxymap
proxywrite unix -       -       n       -       1       proxymap
smtp      unix  -       -       n       -       -       smtp
# When relaying mail as backup MX, disable fallback_relay to avoid MX loops
relay     unix  -       -       n       -       -       smtp
        -o smtp_fallback_relay=
showq     unix  n       -       n       -       -       showq
error     unix  -       -       n       -       -       error
retry     unix  -       -       n       -       -       error
discard   unix  -       -       n       -       -       discard
local     unix  -       n       n       -       -       local
virtual   unix  -       n       n       -       -       virtual
lmtp      unix  -       -       n       -       -       lmtp
anvil     unix  -       -       n       -       1       anvil
scache    unix  -       -       n       -       1       scache
dovecot   unix  -       n       n       -       -       pipe
  flags=DRhu user=vmail:vmail argv=/usr/libexec/dovecot/deliver -d \${recipient}
scan      unix  -       -       n       -       16      smtp
   -o smtp_data_done_timeout=1200
   -o smtp_send_xforward_command=yes
   -o disable_dns_lookups=yes
   -o smtp_enforce_tls=no
127.0.0.1:10026 inet n       -       n       -       16       smtpd
   -o content_filter=
   -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
   -o local_recipient_maps=
   -o relay_recipient_maps=
   -o smtpd_restriction_classes=
   -o smtpd_client_restrictions=
   -o smtpd_helo_restrictions=
   -o smtpd_sender_restrictions=
   -o smtpd_recipient_restrictions=permit_mynetworks,reject
   -o mynetworks_style=host
   -o smtpd_authorized_xforward_hosts=127.0.0.0/8
END

echo
WHITETXT "Writing Dovecot config file"
cat > /etc/dovecot/dovecot.conf <<END
auth_mechanisms = plain login
disable_plaintext_auth = yes
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_location = maildir:/home/vmail/%d/%n
mail_privileged_group = vmail

ssl = required

ssl_cert = <$VMB_SSL_CRT
ssl_key = <$VMB_SSL_KEY

ssl_cipher_list = ALL:!LOW:!SSLv2:!EXP:!aNULL

namespace {
  inbox = yes
  location =
  prefix =
  type = private
}

protocols = imap

service imap-login {
        inet_listener imap {
        port = 0
        }
}

passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf
}
 
userdb {
  driver = prefetch
}
 
userdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
unix_listener auth-master {
    mode = 0600
    user = vmail
  }
user = root
}

protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  log_path = /home/vmail/dovecot-deliver.log
  postmaster_address = $VMB_ADMIN_MAIL
}
END

echo
WHITETXT "Writing Dovecot mysql connection file"
cat > /etc/dovecot/dovecot-sql.conf <<END
driver = mysql
connect = host=$VMB_DB_HOST dbname=$VMB_DB_NAME user=$VMB_DB_USER_NAME password=$VMB_PASSGEN
default_pass_scheme = SSHA512

password_query = SELECT username as user, password as password, \
        homedir AS userdb_home, maildir AS userdb_mail, \
        concat('*:bytes=', quota) AS userdb_quota_rule, uid AS userdb_uid, gid AS userdb_gid \
    FROM mailbox \
        WHERE username = '%Lu' AND active = '1' \
            AND ( access_restriction = 'ALL' OR LOCATE( '%Us', access_restriction ) > 0 )name = '%u'
            
user_query = SELECT homedir AS home, maildir AS mail, \
        concat('*:bytes=', quota) as quota_rule, uid, gid \
    FROM mailbox WHERE username = '%u'
END

echo
WHITETXT "Writing Postfix REJECT filters. Please uncomment/edit to your needs"
WHITETXT "/etc/postfix/config/"

cat > /etc/postfix/config/black_client <<END
#/^.*\@mail\.ru$/        REJECT        Your e-mail was banned!
END

cat > /etc/postfix/config/black_client_ip <<END
#/123\.45\.67\.89/       REJECT        Your IP was banned!
#/123\.45/               REJECT        Your IP-range was banned!
#/xyz\.ua/               REJECT        Your Domain was banned!
#cc\.zxc\.ua/            REJECT        Your Domain was banned!
END

cat > /etc/postfix/config/block_dsl <<END
#/^dsl.*\..*/i                   553 AUTO_DSL Please use your internet provider SMTP Server.
#/.*\.dsl\..*/i                  553 AUTO_DSL2 Please use your internet provider SMTP Server.
#/[a|x]dsl.*\..*\..*/i           553 AUTO_[A|X]DSL Please use your internet provider SMTP Server.
#/client.*\..*\..*/i             553 AUTO_CLIENT Please use your internet provider SMTP Server.
#/cable.*\..*\..*/i              553 AUTO_CABLE Please use your internet provider SMTP Server.
#/pool\..*/i                     553 AUTO_POOL Please use your internet provider SMTP Server.
#/.*dial(\.|-).*\..*\..*/i       553 AUTO_DIAL Please use your internet provider SMTP Server.
#/ppp.*\..*/i                    553 AUTO_PPP Please use your internet provider SMTP Server.
#/dslam.*\..*\..*/i              553 AUTO_DSLAM Please use your internet provider SMTP Server.
#/dslb.*\..*\..*/i               553 AUTO_DSLB Please use your internet provider SMTP Server.
#/node.*\..*\..*/i               553 AUTO_NODE Please use your internet provider SMTP Server.
END

cat > /etc/postfix/config/helo_checks <<END
#/^\[?10\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?$/ REJECT Address in RFC 1918 private network
#/^\[?192\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?$/ REJECT Address in RFC 1918 private network
#/^\[?172\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?$/ REJECT Address in RFC 1918 private network
#/\d{2,}[-\.]+\d{2,}/ REJECT Invalid hostname (D-D)
#/^(((newm|em|gm|m)ail|yandex|rambler|hotbox|chat|rbc|subscribe|spbnit)\.ru)$/ REJECT Faked hostname (\$1)
#/^(((hotmail|mcim|newm|em)ail|post|hotbox|msn|microsoft|aol|news|compuserve|yahoo|google|earthlink|netscape)\.(com|net))$/ REJECT Faked hostname (\$1)
#/[^[] *[0-9]+((\.|-|_)[0-9]+){3}/ REJECT Invalid hostname (ipable)
END

cat > /etc/postfix/config/mx_access <<END
#127.0.0.1      DUNNO 
#127.0.0.2      550 Domains not registered properly
#0.0.0.0/8      REJECT Domain MX in broadcast network 
#10.0.0.0/8     REJECT Domain MX in RFC 1918 private network 
#127.0.0.0/8    REJECT Domain MX in loopback network 
#169.254.0.0/16 REJECT Domain MX in link local network 
#172.16.0.0/12  REJECT Domain MX in RFC 1918 private network 
#192.0.2.0/24   REJECT Domain MX in TEST-NET network 
#192.168.0.0/16 REJECT Domain MX in RFC 1918 private network 
#224.0.0.0/4    REJECT Domain MX in class D multicast network 
#240.0.0.0/5    REJECT Domain MX in class E reserved network 
#248.0.0.0/5    REJECT Domain MX in reserved network
END

cat > /etc/postfix/config/white_client <<END
#/^.*\@mail\.ru$/        PERMIT
END

cat > /etc/postfix/config/white_client_ip <<END
#/91\.214\.209\.5/        PERMIT
END
echo
echo
WHITETXT "Writing ClamSMTP filter config"
cat > /etc/clamsmtpd.conf <<END
# - Comments are a line that starts with a #
# - All the options are found below with sample settings
# The address to send scanned mail to.
# This option is required unless TransparentProxy is enabled
OutAddress: 127.0.0.1:10026
# The maximum number of connection allowed at once.
# Be sure that clamd can also handle this many connections
#MaxConnections: 64
# Amount of time (in seconds) to wait on network IO
#TimeOut: 180
# Keep Alives (ie: NOOP's to server)
#KeepAlives: 0
# Send XCLIENT commands to receiving server
#XClient: off
# Address to listen on (defaults to all local addresses on port 10025)
Listen: 127.0.0.1:10025
# The address clamd is listening on
ClamAddress: /var/run/clamav/clamd.sock
# A header to add to all scanned email
Header: X-Virus-Scanned: ClamAV using ClamSMTP
# Directory for temporary files
TempDirectory: /tmp
# What to do when we see a virus (use 'bounce' or 'pass' or 'drop'
Action: drop
# Whether or not to keep virus files
Quarantine: off
# Enable transparent proxy support
TransparentProxy: off
# User to switch to
User: clam
# Virus actions: There's an option to run a script every time a virus is found.
# !IMPORTANT! This can open a hole in your server's security big enough to drive
# farm vehicles through. Be sure you know what you're doing. !IMPORTANT!
VirusAction: /etc/postfix/valert.sh
END
echo
WHITETXT "Writing ClamSMTP email alert script"
cat > /etc/postfix/valert.sh <<END
#!/bin/sh
#
# v0.1 (2009-04-09)
#
# VirusAction script to get virus alerts via email from ClamSMTP.
#   Based on VirusAction script by Olivier Beyssac <ob@r14.freenix.org>
#
# Sends alerts:
#	  1) to sender if domain part of sender address is local,
#	otherwise to LOCAL recipients;
#	  2)  in any case to explicitly specified recipients, e.g. postmaster
#
# Alexander Moisseev <moiseev@mezonplus.ru>
#

# Local domains (comma separated without spaces)
MYDOMAINS=$VMB_DOMAIN
# Email addresses to send alerts to (comma separated without spaces)
NOTIFY=$VMB_ADMIN_MAIL


MYDOM_RE=.+@`echo "\$MYDOMAINS" |  sed 's/,/$|.+@/g'`$

echo \$MYDOM_RE
if [ X`echo \$SENDER | egrep \$MYDOM_RE` != "X" ];
    then MAILTO=\$SENDER,\$NOTIFY
    else MAILTO=`echo "\$RECIPIENTS" | egrep \$MYDOM_RE | tr '\n' ','`\$NOTIFY
fi

LINE="-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-"

#(date "+%d-%m-%Y %H:%M:%S"
(date
 echo
 echo "Virus name:     \$VIRUS"
 echo "Sender:         \$SENDER"
 echo "Recipient(s):   \$RECIPIENTS"
 echo "SMTP client:    \$CLIENT"
 echo "SMTP server:    \$SERVER"
 echo "Remote client:  \$REMOTE" | tr -d '\r'
 echo
 if [ "x\$EMAIL" != "x" ] && [ -f \$EMAIL ]
 then
	echo "Quarantined to: \$EMAIL"
	echo
	echo Headers follow:
	echo \$LINE
	sed -n '1,/^.$/s/.$//gp' "\$EMAIL"
	echo \$LINE
 fi
) | cat -v | mail -s "[ VIRUS  ALERT ]: \$VIRUS found on \$SERVER" \$MAILTO
END
echo
WHITETXT "============================================================================="
echo
WHITETXT "Now we going to configure opendkim - generating signing key and configs"
echo
echo
read -p "---> Enter your domains: domain1.com domain2.net domain3.eu: " DKIM_DOMAINS
echo
echo
for DOMAIN in ${DKIM_DOMAINS}
do
# Generate folders and keys
mkdir -p /etc/opendkim/keys/${DOMAIN}
opendkim-genkey -D /etc/opendkim/keys/${DOMAIN}/ -d ${DOMAIN} -s default
chown -R opendkim:opendkim /etc/opendkim/keys/${DOMAIN}
cd /etc/opendkim/keys/${DOMAIN}
cp default.private default
# Add key rule to Table
echo "default._domainkey.${DOMAIN} ${DOMAIN}:default:/etc/opendkim/keys/${DOMAIN}/default.private" >> /etc/opendkim/KeyTable
echo "*@${DOMAIN} default._domainkey.${DOMAIN}" >> /etc/opendkim/SigningTable
echo
GREENTXT " DNS records for ${YELLOW}${BOLD}${DOMAIN} "
cat /etc/opendkim/keys/${DOMAIN}/default.txt
echo "_adsp._domainkey.${DOMAIN} IN TXT dkim=unknown"
WHITETXT "============================================================================="
done
echo
WHITETXT "Loading main opendkim config"
cat > /etc/opendkim.conf <<END
## BEFORE running OpenDKIM you must:
## - edit your DNS records to publish your public keys

## CONFIGURATION OPTIONS
PidFile /var/run/opendkim/opendkim.pid
AutoRestart     yes
AutoRestartRate 5/1h
Mode    sv
Syslog  yes
SyslogSuccess   yes
LogWhy  yes
UserID  opendkim:opendkim
Socket  inet:8891@localhost
Umask   002
## SIGNING OPTIONS
Canonicalization        relaxed/simple
Selector        default
MinimumKeyBits 1024

KeyTable        /etc/opendkim/KeyTable
SigningTable    refile:/etc/opendkim/SigningTable
END
echo
echo
WHITETXT "============================================================================="
echo
pause '------> Press [Enter] key to continue'
echo
echo
WHITETXT "============================================================================="
WHITETXT "============================================================================="
echo
VMB_PATH=$(cat /root/adovms/.adovms_index | grep mail | awk '{print $2}')
WHITETXT "Now we will try to edit ViMbAdmin v3 application.ini file:"
WHITETXT "$VMB_PATH/application/configs/application.ini"
cd ${VMB_PATH}
cp ${VMB_PATH}/application/configs/application.ini.dist ${VMB_PATH}/application/configs/application.ini
sed -i 's/defaults.domain.transport = "virtual"/defaults.domain.transport = "dovecot"/' ${VMB_PATH}/application/configs/application.ini
sed -i 's/defaults.mailbox.uid = 2000/defaults.mailbox.uid = 5000/' ${VMB_PATH}/application/configs/application.ini
sed -i 's/defaults.mailbox.gid = 2000/defaults.mailbox.gid = 5000/' ${VMB_PATH}/application/configs/application.ini
sed -i 's/server.pop3.enabled = 1/server.pop3.enabled = 0/' ${VMB_PATH}/application/configs/application.ini
sed -i "s/resources.doctrine2.connection.options.dbname   = 'vimbadmin'/resources.doctrine2.connection.options.dbname   = '${VMB_DB_NAME}'/" ${VMB_PATH}/application/configs/application.ini
sed -i "s/resources.doctrine2.connection.options.user     = 'vimbadmin'/resources.doctrine2.connection.options.user     = '${VMB_DB_USER_NAME}'/" ${VMB_PATH}/application/configs/application.ini
sed -i "s/resources.doctrine2.connection.options.password = 'xxx'/resources.doctrine2.connection.options.password = '${VMB_PASSGEN}'/" ${VMB_PATH}/application/configs/application.ini
sed -i "s/resources.doctrine2.connection.options.host     = 'localhost'/resources.doctrine2.connection.options.host     = '${VMB_DB_HOST}'/" ${VMB_PATH}/application/configs/application.ini
sed -i 's,defaults.mailbox.maildir = "maildir:/srv/vmail/%d/%u/mail:LAYOUT=fs",defaults.mailbox.maildir = "maildir:/home/vmail/%d/%u",'  ${VMB_PATH}/application/configs/application.ini
sed -i 's,defaults.mailbox.homedir = "/srv/vmail/%d/%u",defaults.mailbox.homedir = "/home/vmail/%d/%u",' ${VMB_PATH}/application/configs/application.ini
sed -i 's/defaults.mailbox.password_scheme = "md5.salted"/defaults.mailbox.password_scheme = "dovecot:SSHA512"/' ${VMB_PATH}/application/configs/application.ini
sed -i 's/server.email.name = "ViMbAdmin Administrator"/server.email.name = "eMail Administrator"/' ${VMB_PATH}/application/configs/application.ini
sed -i 's/server.email.address = "support@example.com"/server.email.address = "'${VMB_ADMIN_MAIL}'"/' ${VMB_PATH}/application/configs/application.ini
echo
WHITETXT "Creating ViMbAdmin v3 database tables:"
./bin/doctrine2-cli.php orm:schema-tool:create
echo
WHITETXT "Now edit ${VMB_PATH}/application/configs/application.ini and configure all parameters in the [user] section"
WHITETXT "except securitysalt - easier to do that later when you first run web frontend"
WHITETXT "monitor mail log   tail -f /var/log/maillog"
echo
fi
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"exit")
REDTXT "------> bye"
echo -e "\a\a\a"
exit
;;
###################################################################################
#                               MENU DEFAULT CATCH ALL                            #
###################################################################################
*)
printf "\033c"
;;
esac
done
