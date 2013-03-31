ADOVMS-M
========

##Automated Deployment of Virtual Mail Server<br/>
connection: SSL/TLS<br/>
SMTP SSL Port 465<br/>
IMAP SSL Port 993<br/>
OpenDKIM signature<br/>

*server key file and ssl certificate must be ready installed*<br/>
<br/>

About this setup
----------------
Setting up the framework for an advanced virtual mail server.
<br/><br/><br/>
**This script will be using:**<br/>
*- [ViMbAdmin](https://github.com/opensolutions/ViMbAdmin)*<br/>
*- [Postfix](http://www.postfix.org/) 2.10.0*<br/>
*- [Dovecot](http://dovecot.org/) 2.0.21*<br/>
*- [Dovecot-Mysql](http://wiki2.dovecot.org/AuthDatabase/SQL) 2.0.21*<br/>
*- [OpenDKIM](http://www.opendkim.org/) 2.8.1* <br/>
<br/><br/>
**Prerequisites:**<br/>
meet the follow prerequisites:<br/>
**CentOS 6 x64**<br/>
A supported database server is installed and ready for use<br/>
The Admin has an understanding of basic SQL functions.<br/>
*- MySQL 5.5+*<br/>
<br/>
A webserver installed, ready to use, supporting PHP & setup for virtual hosting<br/>
*- Apache 2*<br/>
*- Nginx*<br/>
*- Lighttpd*<br/>
*- PHP*<br/>
<br/><br/>
Please read the ViMbAdmin documentation on how to configure the web interface.
