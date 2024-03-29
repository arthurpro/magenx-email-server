MagenX e-mail Server
===================

## How to setup mail server with Centos, Postfix, Dovecot, OpenDKIM, ClamAV, ClamSMTP and Roundcube 1.x + ViMbAdmin management interface<br/>

connection: SSL/TLS<br/>
SMTP SSL Port 465<br/>
IMAP SSL Port 993<br/>
OpenDKIM signature<br/>
SMTP Virus Filter<br/>

*server key file and ssl certificate must be installed*<br/>
*php > 5.4 must be installed*<br/>
<br/>

About this setup
----------------
Setting up the framework for an advanced virtual mail server.<br/>
you can easily control unlimited virtual domains, mailboxes and aliases.<br/>
create super admin and domain admin.
<br/><br/><br/>
**This script will be using:**<br/>
*- [Roundcube](http://roundcube.net/) latest*<br/>
*- [ViMbAdmin](https://github.com/opensolutions/ViMbAdmin) latest*<br/>
*- [Postfix](http://www.postfix.org/) latest*<br/>
*- [Dovecot](http://dovecot.org/) latest*<br/>
*- [Dovecot-Mysql](http://wiki2.dovecot.org/AuthDatabase/SQL) latest*<br/>
*- [OpenDKIM](http://www.opendkim.org/) latest* <br/>
*- [Clam AntiVirus](http://www.clamav.net/lang/en/) latest* <br/>
*- [Clam SMTP](http://thewalter.net/stef/software/clamsmtp/) latest*<br/>
<br/><br/>
**Prerequisites:**<br/>
meet the follow prerequisites:<br/>
**CentOS 6 x64**<br/>
A supported database server is installed and ready for use<br/>
The Admin has an understanding of basic SQL functions.<br/>
*- MySQL 5.5+*<br/>
<br/>
A webserver installed, ready to use, supporting PHP > 5.4 & setup for virtual hosting<br/>
*- Apache 2*<br/>
*- Nginx*<br/>
*- Lighttpd*<br/>
*- PHP > 5.4*<br/>
<br/><br/>
Please read the ViMbAdmin documentation on how to configure the web interface.
