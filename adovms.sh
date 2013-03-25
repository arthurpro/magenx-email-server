#!/bin/bash
#
#====================================================================#
#  MagenX - Automated Deployment of Virtual Mail Server              #
#  Copyright (C) 2013 admin@magentomod.com                           #
#  All rights reserved.                                              #
#====================================================================#

ADOVMS_VER="2.1a"

# quick-n-dirty - color, indent, echo, pause, proggress bar settings
function cecho() {
        COLOR='\033[01;37m'     # bold gray
        RESET='\033[00;00m'     # normal white
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "${COLOR}${MESSAGE}${RESET}" | awk '{print "    ",$0}'
}
function cinfo() {
        COLOR='\033[01;34m'     # bold blue
        RESET='\033[00;00m'     # normal white
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "${COLOR}${MESSAGE}${RESET}" | awk '{print "    ",$0}'
}
function cwarn() {
        COLOR='\033[01;31m'     # bold red
        RESET='\033[00;00m'     # normal white
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "${COLOR}${MESSAGE}${RESET}" | awk '{print "    ",$0}'
} 
function cok() {
        COLOR='\033[01;32m'     # bold green
        RESET='\033[00;00m'     # normal white
        MESSAGE=${@:-"${RESET}Error: No message passed"}
        echo -e "${COLOR}${MESSAGE}${RESET}" | awk '{print "    ",$0}'
}

function pause() {
   read -p "$*"
}

function start_progress {
  interval=1
  while true
  do
    echo -ne "#"
    sleep $interval
  done
}

function quick_progress {
  interval=0.05
  while true
  do
    echo -ne "#"
    sleep $interval
  done
}

function long_progress {
  interval=3
  while true
  do
    echo -ne "#"
    sleep $interval
  done
}

function stop_progress {
kill $1
wait $1 2>/dev/null
echo -en "\n"
}

clear
###################################################################################
#                                     START CHECKS                                #
###################################################################################
echo

# root?
if [[ $EUID -ne 0 ]]; then
cwarn "ERROR: THIS SCRIPT MUST BE RUN AS ROOT!"
echo "------> USE SUPER-USER PRIVILEGES."
  exit 1
else
  cok PASS: ROOT!
fi

# do we have CentOS 6?
if grep -q "CentOS release 6" /etc/redhat-release ; then
cok "PASS: CENTOS RELEASE 6"
  else 
cwarn "ERROR: UNABLE TO DETERMINE DISTRIBUTION TYPE."
echo "------> THIS CONFIGURATION FOR CENTOS 6."
echo
  exit 1
fi

# check if x64. if not, beat it...
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
cok "PASS: YOUR ARCHITECTURE IS 64-BIT"
  else
  cwarn "ERROR: YOUR ARCHITECTURE IS 32-BIT?"
  echo "------> CONFIGURATION FOR 64-BIT ONLY."
  echo
  exit 1
fi


# network is up?
host1=74.125.24.106
host2=208.80.154.225
RESULT=$(((ping -w3 -c2 $host1 || ping -w3 -c2 $host2) > /dev/null 2>&1) && echo "up" || (echo "down" && exit 1))
if [[ $RESULT == up ]]; then
cok "PASS: NETWORK IS UP. GREAT, LETS START!"
  else
cwarn "ERROR: NETWORK IS DOWN?"
echo "------> PLEASE CHECK YOUR NETWORK SETTINGS."
echo
echo
  exit 1
fi
echo
###################################################################################
#                                     CHECKS END                                  #
###################################################################################
echo
if grep -q "yes" ~/adovms/.terms >/dev/null 2>&1 ; then
echo "loading menu"
sleep 1
  else
cecho "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo
cecho "BY INSTALLING THIS SOFTWARE AND BY USING ANY AND ALL SOFTWARE"
cecho "YOU ACKNOWLEDGE AND AGREE:"
echo
cecho "THIS SOFTWARE AND ALL SOFTWARE PROVIDED IS PROVIDED AS IS"
cecho "UNSUPPORTED AND WE ARE NOT RESPONSIBLE FOR ANY DAMAGE"
echo
cecho "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
echo
echo
			echo -n "---> Do you agree to these terms?  [y/n][y]:"
			read terms_agree
				if [ "$terms_agree" == "y" ];then
				mkdir -p ~/adovms
				echo "yes" > ~/adovms/.terms
			else
			echo "Exiting"
			echo
		exit 1
		fi
	fi
###################################################################################
#                                  HEADER MENU START                              #
###################################################################################

showMenu () {
printf "\033c"
     echo
		echo
        cecho "Automated Deployment of Virtual Mail Server v.$ADOVMS_VER"
        cecho :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
        echo
        cecho "- For repositories installation enter   :  \033[01;34m repo"
        cecho "- For packages installation enter   :  \033[01;34m packages"
	cecho "- Download and configure vimbadmin :  \033[01;34m vimbadmin"
        cecho "- Download and configure everything   :  \033[01;34m config"
        echo
        cecho :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
		echo
        cecho "- To quit enter:  \033[01;34m exit"
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
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok NOW BEGIN REPOSITORIES INSTALLATION
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
cecho "============================================================================="
echo
echo -n "---> Start EPEL repository installation? [y/n][n]:"
read repoE_install
if [ "$repoE_install" == "y" ];then
        echo
        cok "Running Installation of Extra Packages for Enterprise Linux"
        echo
		rpm  --quiet -q epel-release
           if [ "$?" = 0 ]
              then
              cok "ALREADY INSTALLED"
		else
        echo -n "     PROCESSING  "
		quick_progress &
		pid="$!"
		rpm -Uvh http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm >/dev/null 2>&1
		stop_progress "$pid"
        fi
	else
        cinfo "EPEL repository installation skipped. Next step"
fi
echo
cecho "============================================================================="
echo
echo -n "---> Start CentALT Repository installation? [y/n][n]:"
read repoC_install
if [ "$repoC_install" == "y" ];then
		echo
        cok "Running Installation of CentALT repository"
		echo
		rpm  --quiet -q centalt-release
           if [ "$?" = 0 ]
              then
              cok "ALREADY INSTALLED"
		else
		echo -n "     PROCESSING  "
		quick_progress &
		pid="$!"
		rpm -Uvh http://centos.alt.ru/pub/repository/centos/6/x86_64/centalt-release-6-1.noarch.rpm >/dev/null 2>&1
		stop_progress "$pid"
        fi
	echo
  else
        cinfo "CentALT repository installation skipped. Next step"
fi
echo
cecho "============================================================================="
echo
echo -n "---> Start Repoforge repository installation? [y/n][n]:"
read repoF_install
if [ "$repoF_install" == "y" ];then
		echo
        cok "Running Installation of Repoforge"
		echo
		rpm  --quiet -q rpmforge-release
           if [ "$?" = 0 ]
              then
              cok "ALREADY INSTALLED"
		else
        echo -n "     PROCESSING  "
		quick_progress &
		pid="$!"
		rpm -Uvh http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.2-2.el6.rf.x86_64.rpm >/dev/null 2>&1
		stop_progress "$pid"
        fi
	echo
  else
        cinfo "Repoforge installation skipped. Next step"
fi
echo 
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok REPOSITORIES INSTALLATION FINISHED
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
echo
echo
pause "---> Press [Enter] key to show menu"
printf "\033c"
;;
"packages")
echo
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok NOW INSTALLING POSTFIX AND DOVECOT
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
echo
echo -n "---> Start mail packages installation? [y/n][n]:"
read mail_install
if [ "$mail_install" == "y" ];then
		echo
        cok "Running mail packages installation"
		echo
			echo -n "     PROCESSING  "
		long_progress &
		pid="$!"
		yum -y -q install postfix dovecot dovecot-mysql dovecot-pigeonhole git subversion >/dev/null 2>&1
		stop_progress "$pid"
		echo
        cok "Running opendkim installation"
		echo
		     echo -n "     PROCESSING  "
		start_progress &
		pid="$!"
		yum --enablerepo=epel-testing install opendkim >/dev/null 2>&1
		stop_progress "$pid"
		echo
          rpm  --quiet -q postfix dovecot dovecot-mysql dovecot-pigeonhole opendkim git subversion
             if [ $? = 0 ]
                then
		echo
                cok "INSTALLED"
		     else
             cwarn "ERROR"
		    exit
          fi
	echo
		chkconfig postfix on
		chkconfig dovecot on
		chkconfig opendkim on
		chkconfig exim off
		chkconfig sendmail off
		alternatives --set mta /usr/sbin/sendmail.postfix
  else
        cinfo "mail packages installation skipped. Next step"
fi
echo
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok FINISHED PACKAGES INSTALLATION
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"vimbadmin")
echo
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok NOW DOWNLOADING ViMbAdmin
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
echo -n "---> Download and configure ViMbAdmin? [y/n][n]:"
read vmb_down
if [ "$vmb_down" == "y" ];then
     read -e -p "---> Edit your installation folder full path: " -i "/var/www/html/vmb" VMB_PATH
	 echo
        echo "  ViMbAdmin will be installed into:" 
		cok $VMB_PATH
		echo
		pause '------> Press [Enter] key to continue'
		echo
		mkdir -p $VMB_PATH
        cd $VMB_PATH
		echo
		###################################################
		git config --global url."https://".insteadOf git://
		###################################################
			echo -n "     PROCESSING  "
		long_progress &
		pid="$!"
        git clone git://github.com/opensolutions/ViMbAdmin.git .  >/dev/null 2>&1
		stop_progress "$pid"
		echo
		echo "  Installing Third Party Libraries"
		echo
        cd $VMB_PATH
		echo
			echo -n "     PROCESSING  "
		long_progress &
		pid="$!"
        ./bin/library-init.sh  >/dev/null 2>&1
        stop_progress "$pid"

cat > ~/adovms/.adovms_index <<END
mail	$VMB_PATH
END
	fi
echo
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok FINISHED ViMbAdmin INSTALLATION
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"config")
echo
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
cok NOW CONFIGURING POSTFIX, DOVECOT, OPENDKIM, ViMbAdmin AND NGINX
echo @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
echo
printf "\033c"
echo
cecho "CREATING Virtual mail User and Group"
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /home/vmail -m -s /sbin/nologin
echo
cecho "CREATING ViMbAdmin DATABASE AND DATABASE USER"
echo
echo -n "---> Generate ViMbAdmin strong password? [y/n][n]:"
read vmb_pass_gen
if [ "$vmb_pass_gen" == "y" ];then
echo
        VMB_PASSGEN=$(head -c 500 /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 15 | head -n 1)
                cecho "ViMbAdmin database password: \033[01;31m $VMB_PASSGEN"
                cok "!REMEMBER IT AND KEEP IT SAFE!"
        fi
	echo
echo
read -p "---> Enter MySQL ROOT password : " MYSQL_ROOT_PASS
read -p "---> Enter ViMbAdmin database host : " VMB_DB_HOST
read -p "---> Enter ViMbAdmin database name : " VMB_DB_NAME
read -p "---> Enter ViMbAdmin database user : " VMB_DB_USER_NAME
echo
mysql -u root -p$MYSQL_ROOT_PASS <<EOMYSQL
CREATE USER '$VMB_DB_USER_NAME'@'$VMB_DB_HOST' IDENTIFIED BY '$VMB_PASSGEN';
CREATE DATABASE $VMB_DB_NAME;
GRANT ALL PRIVILEGES ON $VMB_DB_NAME.* TO '$VMB_DB_USER_NAME'@'$VMB_DB_HOST' WITH GRANT OPTION;
exit
EOMYSQL
echo
echo
cecho "============================================================================="
echo
echo -n "---> Load preconfigured postfix dovecot configs? [y/n][n]:"
read load_configs
if [ "$load_configs" == "y" ];then
echo
cwarn "YOU HAVE TO CHECK THEM AFTER ANYWAY"
echo
mkdir -p /etc/postfix/mysql
mkdir -p /etc/postfix/config
cecho "Writing Postfix/ViMbAdmin mysql connection files"
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
cecho "Writing Postfix main.cf file"
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
myorigin = \$myhostname

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

notify_classes = bounce, delay, policy, protocol, resource, software
error_notice_recipient = $VMB_ADMIN_MAIL

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
cecho "Writing Postfix master.cf file"
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
END

echo
cecho "Writing Dovecot config file"
cat > /etc/dovecot/dovecot.conf <<END
auth_mechanisms = plain login
disable_plaintext_auth = yes
log_timestamp = "%Y-%m-%d %H:%M:%S "
mail_location = maildir:/home/vmail/%d/%n
mail_privileged_group = mail

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
passdb {
  args = /etc/dovecot/dovecot-sql.conf
  driver = sql
}
protocols = imap

service imap-login {
        inet_listener imap {
        port = 0
        }
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

userdb {
  args = uid=5000 gid=5000 home=/home/vmail/%d/%n allow_all_users=yes
  driver = static
}
protocol lda {
  auth_socket_path = /var/run/dovecot/auth-master
  log_path = /home/vmail/dovecot-deliver.log
  postmaster_address = $VMB_ADMIN_MAIL
}
END

echo
cecho "Writing Dovecot mysql connection file"
cat > /etc/dovecot/dovecot-sql.conf <<END
driver = mysql
connect = host=127.0.0.1 dbname=$VMB_DB_NAME user=$VMB_DB_USER_NAME password=$VMB_PASSGEN
default_pass_scheme = PLAIN-MD5
password_query = SELECT username as user, password FROM mailbox WHERE username = '%u'
END

echo
cecho "Writing Postfix REJECT filters. Please uncomment/edit to your needs"
cecho "/etc/postfix/config/"

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
cecho "============================================================================="
echo
cecho "Now we going to configure opendkim - generating signing key and configs"
echo
pause '------> Press [Enter] key to proceed'
echo
mkdir -p /etc/opendkim/keys/$VMB_DOMAIN
opendkim-genkey -D /etc/opendkim/keys/$VMB_DOMAIN/ -d $VMB_DOMAIN -s default
chown -R opendkim:opendkim /etc/opendkim/keys/$VMB_DOMAIN
cd /etc/opendkim/keys/$VMB_DOMAIN
cp default.private default
cecho "Loading main opendkim config"

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
KeyFile /etc/opendkim/keys/$VMB_DOMAIN/default.private
KeyTable        /etc/opendkim/KeyTable
SigningTable    refile:/etc/opendkim/SigningTable
END
echo
cecho "Loading opendkim KeyTable"

cat > /etc/opendkim/KeyTable <<END
# To use this file, uncomment the #KeyTable option in /etc/opendkim.conf,
# then uncomment the following line and replace example.com with your domain
# name, then restart OpenDKIM. Additional keys may be added on separate lines.

default._domainkey.$VMB_DOMAIN $VMB_DOMAIN:default:/etc/opendkim/keys/$VMB_DOMAIN/default.private
END
echo
cecho "Loading opendkim SigningTable"

cat > /etc/opendkim/SigningTable <<END
# The following wildcard will work only if
# refile:/etc/opendkim/SigningTable is included
# in /etc/opendkim.conf.

*@$VMB_DOMAIN default._domainkey.$VMB_DOMAIN
END
echo
cecho "============================================================================="
cecho "============================================================================="
cecho "Update the DNS records"
cecho "This is the final part. You need to add a TXT entry default._domainkey"
echo
DKIM_RECORD=$(cat /etc/opendkim/keys/$VMB_DOMAIN/default.txt)
cok "$DKIM_RECORD"
echo
cecho "You should also add another TXT Record to your zone file"
cok "_adsp._domainkey.$VMB_DOMAIN IN TXT dkim=unknown"
echo
pause '------> Press [Enter] key to continue'
echo
echo
cecho "============================================================================="
cecho "============================================================================="
echo
VMB_PATH=$(cat ~/adovms/.adovms_index | grep mail | awk '{print $2}')
cecho "Now we will try to edit ViMbAdmin application.ini file:"
cecho "$VMB_PATH/application/configs/application.ini"
cd $VMB_PATH
cp $VMB_PATH/application/configs/application.ini.dist $VMB_PATH/application/configs/application.ini
sed -i 's/defaults.domain.transport = "virtual"/defaults.domain.transport = "dovecot"/' $VMB_PATH/application/configs/application.ini
sed -i 's/defaults.mailbox.uid = 2000/defaults.mailbox.uid = 5000/' $VMB_PATH/application/configs/application.ini
sed -i 's/defaults.mailbox.gid = 2000/defaults.mailbox.gid = 5000/' $VMB_PATH/application/configs/application.ini
sed -i 's/server.pop3.enabled = 1/server.pop3.enabled = 0/' $VMB_PATH/application/configs/application.ini
sed -i "196i resources.doctrine.connection_string = \"mysql://$VMB_DB_USER_NAME:$VMB_PASSGEN@$VMB_DB_HOST/$VMB_DB_NAME\"" $VMB_PATH/application/configs/application.ini
echo
cecho "Creating ViMbAdmin database tables:"
./bin/doctrine-cli.php create-tables
echo
cecho "Now edit $VMB_PATH/application/configs/application.ini and configure all parameters in the [user] section"
cecho "except securitysalt - easier to do that later when you first run web frontend"
cecho "monitor mail log at tail -f /var/log/maillog"
echo
fi
echo
pause '------> Press [Enter] key to show menu'
printf "\033c"
;;
"exit")
cwarn "------> Hasta la vista, baby..."
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
