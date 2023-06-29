# KODE KLOUD NOTES
https://github.com/chmvreddy/kodekloud

>## KodeKloud Application Architecture
Nautilus deployment architecture can be viewed [here](https://www.lucidchart.com/documents/edit/58e22de2-c446-4b49-ae0f-db79a3318e97/0_0?shared=true)

The Nautilus is a three-tier application and is deployed in the Stratos Datacenter in the North America Region.

1. **Data Tier**: The Data tier is the layer that stores data with the retrieval storage and execution methods made by the application layer. We are making use of MariaDB which is one of the most popular open source relational databases.

1. **Application Tier**: Makes use of a LAMP which is a stack of open-source software that can be used to create web applications. LAMP is an acronym that usually consists of the Linux OS, the Apache HTTP Server, a MySQL relational DBMS (like MariaDB), and PHP.

1. **Client Tier**: The application client which in this case is a web browser software that processes and displays HTML resources, issues HTTP requests for resources, and processes HTTP responses.

1. **Load Balancer**: Nginx is used for HTTP Load Balancing to distribute requests through multiple application servers.

## Shared Services
1. **Storage Filer**: A NAS (Network Attached Storage) filer is used to provide reliable and stable external storage for the application tier servers.
1. **SFTP Server**: SFTP, which stands for SSH File Transfer Protocol is used to transfer data amongst two remote systems.
1. **Backup Server**: A staging backup system used for short term archival.
1. **Jump Server**: The intermediary host or an SSH gateway to a remote network hosting the Nautilus application.

<br>

>## KodeKloud Infrastructure Details

<br>

# SYSADMIN TASKS


<br>

>## Linux Sysadmin Commands

<br>

> TS: (202207301400)

1. ### Create a Linux user with non-interactive shell
    * check if the user exists: `sudo id steve` 
    * `sudo useradd steve -s /sbin/nologin` 
    * confirm creation of user: `sudo cat /etc/passwd | grep steve `


1. ### Create a Linux user with interactive shell
    * `sudo useradd -d /home/steve -g developers -s /bin/bash steve`
        * -d: home directory | -g: user's group | -s: user's default shell
1. ### Create a user without a home directory
    * `sudo useradd -M steve`
<br>

> TS: (202207311638)

1. Make a script executable for all users: `sudo chmod a+rx filename`
    * To make a file executable- seems the read permission needs to also be provided. **TODO**: <u>research whether this is valid.</u>


> TS (202208031915)

1. check system timezone and other datetime related info: `timedatectl`
1.  available timezones: `timedatectl list-timezones`
1. update timezone: `sudo timedatectl set-timezone <timezone name>`
1. can also be done by creating a symlink from the time zone in zoneinfo to local time in /etc/: `sudo ln -s /usr/share/zoneinfo/America/New_York /etc/localtime`

> TS (202208042105)

<br>

### $Run Levels$

A run level is a state of **init** and the whole system that defines what system services are operating.

|0|Halt the system|
|---|---|
|1|Single user mode (for special administration)|
|2|Local Multiuser with Networking but no network service like NFS|
|3|Full Multiuser with Networking|
|4|Not Used (User definable)|
|5|Full Multiuser with Networking and X Window (GUI)
|6|Reboot|

Services that get started at a certain runtime are determined by the contents of the various rcN.d directories. Most distributions locate these directories either at /etc/init.d/rcN.d or /etc/rcN.d. (Replace the N with the run-level number.)

In each run-level you will find a series of if links pointing to start-up scripts located in /etc/init.d. The names of these links all start as either K or S, followed by a number. If the name of the link starts with an S, then that indicates the service will be started when you go into that run level. If the name of the link starts with a K, the service will be killed (if running).

The number following the K or S indicates the order the scripts will be run. Here is a sample of what an /etc/init.d/rc3.d may look like.
`ls -l /etc/init.d/rc3.d`

    lrwxrwxrwx  1 root root 10 2004-11-29 22:09 K12nfsboot -> ../nfsboot
    lrwxrwxrwx  1 root root  6 2005-03-29 13:42 K15xdm -> ../xdm
    lrwxrwxrwx  1 root root  9 2004-11-29 22:08 S01pcmcia -> ../pcmcia
    lrwxrwxrwx  1 root root  9 2004-11-29 22:06 S01random -> ../random

<dd>inittab is no longer used when using systemd.
systemd uses 'targets' instead of runlevels. By default, there are two main targets:

* multi-user.target: analogous to runlevel 3
* graphical.target: analogous to runlevel 5

To view current default target, run:
`systemctl get-default`

To set a default target, run:
`systemctl set-default TARGET.target`</dd>

> TS (202208052239)

1. copy file with parent structure: `cp --parents src dest`
1. find files: `find <search folder> -type [f|d] -user <fileowner> -group <groupowner> -name '*.txt'`
1. find and copy multiple files at once: `find . -type  f -name '*.html' -exec cp --parents {} /some_folder \;`

<br>

>TS (202208072030)

DNS name servers are stored in `/etc/resolv.conf`. Sample file output:

```bash
cat /etc/resolv.conf
search stratos.xfusioncorp.com
nameserver 8.8.8.8 
nameserver 127.0.0.11
options ndots:0

#The search entry is used to complete non-FQDN site searches.
#There can be up to 8 entries in the search line(256 xters)
#the file takes a maximum of 3 name servers.
```
> TS (202208090830)

//TODO: quick description of NTP servers
The Network Time Protocol (NTP) is a protocol used to synchronize computer system clock automatically over a networks. The machine can have the system clock use Coordinated Universal Time (UTC) rather than local time.

    1  cat /etc/ntp.conf
    2  yum install ntp -y
    3  vi /etc/ntp.conf
    4  cat /etc/ntp.conf
    5  systemctl enable ntp
    5  systemctl enable ntpd
    6  systemctl restart ntpd;
    7  systemctl status ntpd;
    8  ntpstat

Chrony is now the default NTP implementation package on the latest versions of Linux operating systems such as CentOS, RHEL, Fedora and Ubuntu/Debian among others and comes pre-installed by default.

```bash
#####installation############
$ sudo apt-get install chrony    [On Debian/Ubuntu]
$ sudo yum  install chrony       [On CentOS/RHEL]
$ sudo dnf install chrony        [On Fedora 22+]

####start and enable to start automatically on startup####
$ systemctl enable --now chronyd
$ systemctl status chronyd

######check if chronyc is running and active connections#####
$ chronyc activity

####check server being synchronized with#####
$ chronyc tracking

#####configure chrony time sources#####
edit the chrony.conf file to add time servers

$ vi /etc/chrony/chrony.conf  #Ubuntu/Debian
$ vi /etc/chrony.conf         #CentOS/RHEL/Fedora

#####pool of timeservers rather than individual servers####
add 'pool <server address>' to chrony.conf

#####restart chrony service after making changes#####
$ sudo systemctl restart chrony		
OR
$ systemctl restart chronyd
```

> TS (202208102110)

### **Linux Banner**

1. message of the day: modify[or replace] `/etc/motd` with the desired banner - RHEL/CentOS; Ubuntu `/etc/update-motd.d`
1. motd messages are executable scripts
1. use `scp -r <source file> username@host:<destination>` to copy file from jump server to remote system.
1. `openssh-clients` needs to be installed on the remote server in order to use `scp` for copying files from jump host to remote server.
1. I can actually run commands in the remote server from the jump host without logging into the remote server directly. : `ssh -t username@host 'sudo mv src dest'`



<br>

>TS (202208120105)

<br>

### **Collaborative directories**

directories created with permissions that allow only the specified group to have access/control to/over the directory.

1. create the directory
1. change ownership to the desired group
1. change the file permission to either allow only the group or root and group.

```bash
mkdir -p /steve/onuche
chgrp -R dad /steve
chmod -R 2770 /steve
```
<br>

> TS (0202208130954)

### **Passwordless ssh access to remote server:**

1. check the client system for any existing ssh key.
1. if none, create an ssh key pair
1. copy the pub key to the remote host's authorized key files.

```bash
$ ls ~/.ssh/id_*
$ ssh-keygen -t [rsa, ed25519, etc] -b 4096 -C "your_email@domain.com"
$ ssh-copy-id remote_username@server_ip_address
#if ssh-copy-id isn't available, use this:
cat ~/.ssh/id_rsa.pub | ssh remote_username@server_ip_address "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```
<br>

> TS (202208152100)

### **Linux Remote Copy**

1. Uses SCP: Secure copy protocol.
1. enables network copying of files within a local system,  between local and remote hosts or between two remote systems
1. Requires ssh to be active in local and remote systems.

syntax:
~~~bash
scp [OPTIONS] [[user@]src_host:]file1 [[user@]dest_host:]file2

OPTIONS: -P|p|r|q|C
~~~
<br>

> TS(202208152245)

### **Change User Expiry Date**
```bash
chage -E yyyy-mm-dd username
-E -1 #never expire
```

<br>

> TS(202208172335)

### **Linux Postfix Troubleshooting**
```bash
systemctl start postfix
cat /etc/postfix/main.cf |grep inet_interface
vi /etc/postfix/main.cf #comment out inet_interfaces = localhost and uncomment inet_interfaces = all
cat /etc/postfix/main.cf |grep inet_interface
systemctl start postfix
systemctl status postfix
telnet stmail01[localhost] 25
```

<br>

> TS(202208190700)

### Mariadb Troubleshooting

for mariadb to run, file name must be 'mysql'.
owner and group must be 'mysql'

`systemctl status mariadb.service -l` #check service status
`ls /var/lib/` # check file user and group ownership and file name

change ownership or file name as appropriate

`systemctl start mariadb` to start the service.

//TODO: what does /var/ do in linux?

<br>

> TS(202208211500)

### **Disable Root Login**

```
ssh tony@stapp01

ssh steve@stapp02

ssh banner@stapp03

systemctl status sshd -l
vi /etc/ssh/sshd_config
#change permitRootLogin yes to 'no' and uncomment
systemctl restart sshd
```

<br>

> TS(202208221745)

### **Using sed**

```bash
# sed -> stream editor [used for find and replace in a given input file]

#syntax:
sed -i 's/old_string/new_string/g' file.ext
# -i -> make the change in the file; defualt behavior is to output the result to screen
# /g -> globaL. change all occurrences rather than the first.
#s / -> substitute.
# /gI -> case insensitive find and replace.
```
<br>

> TS(202208240738)

### **Create a cron job**

```bash
yum install cronie -y
systemctl start crond
systemctl status crond
crontab -e
'*/5 * * * * root echo hello > /tmp/cron_text'
watch -n 5 ls -l /tmp/
```
<br>

> TS(202208271900)

### **Linux GPG Encryption**
```bash
# login and switch to root user
> ssh natasha@ststor01
> sudo -i
> Bl@kW

# import public and private keys to GPG
> cd /home/ && ll
> gpg --import public_key.asc
> gpg --import private_key.asc

# verify keys were successfully imported by listing public and private keys
> gpg --list-keys #public key
> gpg --list-secret-keys #private key

# perform file encryption and output result to named filen in same dir
> gpg --encrypt -r kodekloud@kodekloud.com --armor < encrypt_me.txt -o encrypted_me.asc

#perform file decryption
gpg --decrypt decrypt_me.asc > decrypted_me.txt 

# confirm that encryption was applied
ls -l
cat encrypt_me.txt
cat encrypted_me.asc
cat decrypt_me.asc
cat decrypted_me.txt
```

<br>

> TS(202208291800)

TASK:
We are working on hardening Apache web server on all app servers. As a part of this process we want to add some of the Apache response headers for security purpose. We are testing the settings one by one on all app servers. As per details mentioned below enable these headers for Apache:

Install httpd package on App Server 3 using yum and configure it to run on 6100 port, make sure to start its service.

Create an index.html file under Apache's default document root i.e /var/www/html and add below given content in it.

Welcome to the xFusionCorp Industries!

Configure Apache to enable below mentioned headers:

X-XSS-Protection header with value 1; mode=block
X-Frame-Options header with value SAMEORIGIN
X-Content-Type-Options header with value nosniff

Note: You can test using curl on the given app server as LBR URL will not work for this task.

```bash
#install apache server
rpm -aq | grep httpd #chk if apache is installed
sudo yum install httpd -y

#edit the config files to make the changes as per requirements

vi /etc/httpd/conf/httpd.conf

Listen 6100
Header set X-XSS-Protection "1; mode-block"
Header always append X-Frame-Options SAMEORIGIN
Header set X-Content-Type-Options nosniff
#save and exit

#create index.html

vi /var/www/html/index.html
Welcome to the xFusionCorp Industries!
#save and exit

#start and enable the server daemon
sudo systemctl start httpd
sudo systemctl enable httpd
sudo systemctl status httpd

#check the port the server listens on and try to return the index file.

curl [-i] http://localhost:6100

#End
```
<br>

> TS(202208301830)

### **Application Security**

TASK:

<blockquote>We have a backup management application UI hosted on Nautilus's backup server in Stratos DC. That backup management application code is deployed under Apache on the backup server itself, and Nginx is running as a reverse proxy on the same server. Apache and Nginx ports are 3000 and 8094, respectively. We have iptables firewall installed on this server. Make the appropriate changes to fulfill the requirements mentioned below:

We want to open all incoming connections to Nginx's port and block all incoming connections to Apache's port. Also make sure rules are permanent.</blockquote>

```bash
systemctl status iptables

ss -tlnp |grep httpd

ss -tlnp |grep nginx

systemctl start iptables

systemctl status iptables

iptables -A INPUT -p tcp --dport 8098 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --dport 3003 -m conntrack --ctstate NEW -j REJECT

iptables -L --line-numbers

iptables -R INPUT 5 -p icmp -j REJECT

service iptables save
```
<br>

> TS(202209012000)

### **Linux logrotate**

TASK:

<blockquote>
The Nautilus DevOps team is ready to launch a new application, which they will deploy on app servers in Stratos Datacenter. They are expecting significant traffic/usage of squid on app servers after that. This will generate massive logs, creating huge log files. To utilise the storage efficiently, they need to compress the log files and retain them for a maximum of 3 weeks. Check the requirements shared below:

a. In all app servers install squid package.

b. Using logrotate configure squid logs rotation to monthly and keep only 3 rotated.

(If by default log rotation is set, then please update configuration as needed)
</blockquote>

```bash
> sudo -i
> yum install squid -y
> ls -l /etc/lograte.d
> cat /etc/logrotate.d/squid
> vi /etc/logrotate.d/squid #edit config as per reqt
> systemctl start squid
> systemctl status squid
```

<br>

> TS(20220921800)

### **Configure Local Yum repos**

TASK:
<blockquote>The Nautilus production support team and security team had a meeting last month in which they decided to use local yum repositories for maintaing packages needed for their servers. For now they have decided to configure a local yum repo on Nautilus Backup Server. This is one of the pending items from last month, so please configure a local yum repository on Nautilus Backup Server as per details given below.

a. We have some packages already present at location /packages/downloaded_rpms/ on Nautilus Backup Server.

b. Create a yum repo named localyum and make sure to set Repository ID to localyum. Configure it to use package's location /packages/downloaded_rpms/.

c. Install package httpd from this newly created repo.</blockquote>
```bash
sudo -i
yum repolist #list the available local repos
vi /etc/yum.repos.d/localym.repo #create a repo in the /etc/yum.repos.d/ directory. All repos must reside in this dir and must end with a .repo ext. include the following lines in the file:
Repository ID
Name
Baseurl
Enabled
'
[local_yum]

name=local_yum

baseurl=file:///packages/downloaded_rpms/

enabled = 1

gpgcheck = 0
'
# packages may now be installed from the baseurl -> file.
```
Notes:

[Link to additional resource](https://www.digitalocean.com/community/tutorials/how-to-set-up-and-use-yum-repositories-on-a-centos-6-vps)


<br>

> TS(202209072330)

### **Setup SSL for Nginx**

TASK:
<blockquote>
The system admins team of xFusionCorp Industries needs to deploy a new application on App Server 3 in Stratos Datacenter. They have some pre-requites to get ready that server for application deployment. Prepare the server as per requirements shared below:

Install and configure nginx on App Server 3.

On App Server 3 there is a self signed SSL certificate and key present at location /tmp/nautilus.crt and /tmp/nautilus.key. Move them to some appropriate location and deploy the same in Nginx.

Create an index.html file with content Welcome! under Nginx document root.

For final testing try to access the App Server 3 link (either hostname or IP) from jump host using curl command. For example curl -Ik https://[app-server-ip]/.
</blockquote>

```bash
ssh tony@stapp03

yum install epel-release && yum install nginx -y

cp /tmp/nautilus.crt /etc/pki/CA/certs/;
cp /tmp/nautilus.key /etc/pki/CA/private/;

rm /usr/share/nginx/html/index.html
vi /usr/share/nginx/html/index.html -> Welcome!

vi /etc/nginx/nginx.conf ->
	edit server_name {172.16.238.12},
    ssl_certificate {"/etc/pki/CA/certs/nautilus.crt"},
    ssl_certificate_key {"/etc/pki/CA/private/nautilus.key"}
    uncomment 'Load configuration files for the default server block section'

systemctl start nginx && systemctl status nginx

exit

curl -Ik https://stapp03
```

<br>

> TS(202209091830)

### **Linux bash scripts**

TASK:
<blockquote>
The production support team of xFusionCorp Industries is working on developing some bash scripts to automate different day to day tasks. One is to create a bash script 
for taking websites backup. They have a static website running on App Server 1 in Stratos Datacenter, and they need to create a bash script named blog_backup.sh which 
should accomplish the following tasks. (Also remember to place the script under /scripts directory on App Server 1)


a. Create a zip archive named xfusioncorp_blog.zip of /var/www/html/blog directory.

b. Save the archive in /backup/ on App Server 1. This is a temporary storage, as backups from this location will be clean on weekly basis. Therefore, we also need to save 
this backup archive on Nautilus Backup Server.

c. Copy the created archive to Nautilus Backup Server server in /backup/ location.

d. Please make sure script wont ask for password while copying the archive file. Additionally, the respective server user (for example, tony in case of App Server 1) 
must be able to run it.
</blockquote>

```bash
# connect to the app server
ssh tony@stapp01

# create the backup script in the /scripts folder
vi /scripts/blog_backup.sh
#content(without the quotes):
'
#!/bin/bash

zip -r /backup/xfusioncorp_blog.zip /var/www/html/blog
scp /backup/xfusioncorp_blog.zip clint@stbkp01:/backup/
'

# enable ssh access to the backup server and test access
ls ~/.ssh/id_* #check for existing ssh key pair
ssh-keygen -t rsa
ssh-copy-id clint@stbkp01
ssh clint@stbkp01

# make script executable for user and run script

cd /scripts
sudo chmod +x blog_backup.sh
ls -l #check file permission
sh blog_backup.sh (or ./blog_backup.sh)

# validate output on backup server

ssh clint@stbkp01
ll /backup
```

<br>

> TS(202209102130)

### **Apache Redirects**

TASK:
<blockquote>
The Nautilus devops team got some requirements related to some Apache config changes. They need to setup some redirects for some URLs. There might be some more changes need to be done. Below you can find more details regarding that:

httpd is already installed on app server 3. Configure Apache to listen on port 8088.

Configure Apache to add some redirects as mentioned below:

a.) Redirect http://stapp03.stratos.xfusioncorp.com:<Port>/ to http://www.stapp03.stratos.xfusioncorp.com:<Port>/ i.e non www to www. This must be a permanent redirect i.e 301

b.) Redirect http://www.stapp03.stratos.xfusioncorp.com:<Port>/blog/ to http://www.stapp03.stratos.xfusioncorp.com:<Port>/news/. This must be a temporary redirect i.e 302.
</blockquote>

```bash
# connect to the app server and switch to root user
ssh banner@stapp03
sudo -i

# confirm the apache installation and configuration
rpm -qa | grep httpd
cat /etc/httpd/conf/httpd.conf | grep Listen
cat /etc/httpd/conf/httpd.conf | grep redirect

# update the port to listen on in the configuration to port 5003
vi /etc/httpd/conf/httpd.conf
cat /etc/httpd/conf/httpd.conf |grep Listen 


# update the permanent and temporary redirects per the requirements -> creare a main.conf file
ll /etc/httpd/conf.d/
vi /etc/httpd/conf.d/main.conf

<VirtualHost *:8088>
ServerName stapp03.stratos.xfusioncorp.com
Redirect 301 / http://www.stapp03.stratos.xfusioncorp.com:8088/
</VirtualHost>

<VirtualHost *:8088>
ServerName www.stapp03.stratos.xfusioncorp.com:8088/blog/
Redirect 302 /blog/ http://www.stapp03.stratos.xfusioncorp.com:8088/news/
</VirtualHost>

cat  /etc/httpd/conf.d/main.conf

# restart service and check status
systemctl restart httpd
systemctl status  httpd

# Validate the task
curl http://stapp02.stratos.xfusioncorp.com:8083/
curl http://www.stapp02.stratos.xfusioncorp.com:8083

curl http://www.stapp02.stratos.xfusioncorp.com:8083/blog/
curl http://www.stapp02.stratos.xfusioncorp.com:8083/news/
```

<br>

> TS(202209122250)

### **Web Server Security**

TASK:
<blockquote>
During a recent security audit, the application security team of xFusionCorp Industries found security issues with the Apache web server on Nautilus App Server 2 server in Stratos DC. They have listed several security issues that need to be fixed on this server. Please apply the security settings below:

a. On Nautilus App Server 2 it was identified that the Apache web server is exposing the version number. Ensure this server has the appropriate settings to hide the version number of the Apache web server.

b. There is a website hosted under /var/www/html/news on App Server 2. It was detected that the directory /news lists all of its contents while browsing the URL. Disable the directory browser listing in Apache config.

c. Also make sure to restart the Apache service after making the changes.
</blockquote>


```bash
# Connect to the App server via SSH
ssh steve@stapp02

# Switch to  root user : 
sudo -i

# Check the existing Apache HTTPd service status 
systemctl status httpd

# Verify the existing configuration 
cat /etc/httpd/conf/httpd.conf  |grep ServerTokens
cat /etc/httpd/conf/httpd.conf  |grep ServerSignature
cat /etc/httpd/conf/httpd.conf  |grep Indexes

# Edit the /etc/httpd/conf/httpd.conf file and add the below lines and save the file
vi /etc/httpd/conf/httpd.conf

press / and type the word Options and Press n to find the next occurrence

#delete  Indexes from Options Indexes FollowSymLinks to Disable Directory Browser Listing 
Options FollowSymLinks 

# Go to the end of the line and add below lines for hiding the server version number
# ServerTokens Prod
# ServerSignature Off

# Verify the changes
cat /etc/httpd/conf/httpd.conf  |grep ServerTokens
cat /etc/httpd/conf/httpd.conf  |grep ServerSignature
cat /etc/httpd/conf/httpd.conf  |grep Indexes


cat /etc/httpd/conf/httpd.conf  |grep ServerTokens
#ServerTokens Prod
cat /etc/httpd/conf/httpd.conf  |grep ServerSignature
#ServerSignature Off
cat /etc/httpd/conf/httpd.conf  |grep Indexes
#Indexes Includes FollowSymLinks SymLinksifOwnerMatch #ExecCGI MultiViews

# Save the config file, start the httpd services
systemctl start httpd
systemctl status httpd

# Validate Apache httpd is running or not
curl -I http://stapp02:8080
curl -I http://stapp02:8080/news/


#Vi Editing Tips
 #   The basic steps to perform a search in Vim are as follows:

#Press /.
#Type the search pattern.
#Press Enter to perform the search.
#Press n to find the next occurrence or N to find the previous occurrence.
#Search for Whole Word
```

<br>

> TS(202209172320)

### **Linux Postfix Mail Server**

TASK:
<blockquote>
xFusionCorp Industries has planned to set up a common email server in Stork DC. After several meetings and recommendations they have decided to use postfix as their mail transfer agent and dovecot as an IMAP/POP3 server. We would like you to perform the following steps:



Install and configure postfix on Stork DC mail server.

Create an email account ammar@stratos.xfusioncorp.com identified by TmPcZjtRQx.

Set its mail directory to /home/ammar/Maildir.

Install and configure dovecot on the same server.
</blockquote>

```bash
# login to mail server and switch to root user
ssh groot@stmail01
sudo -i

# check if the postfix and dovecot packages have been installed
rpm -qa | grep postfix 
rpm -qa | grep dovecot

#install postfix
yum install postfix -y

#configure postfix
vi /etc/postfix/main.cf
    # edit the following lines as follows
    :set nu
    #line 76 - uncomment
    'myhostname = stmail01.stratos.xfusioncorp.com'
    #line 83 - uncomment
    'mydomain = stratos.xfusioncorp.com'
    #line 99 - uncomment
    #line 113 - uncomment
    #line 165 - uncomment
    #line 264 - uncomment
    'mynetworks = 172.16.238.0/24, 127.0.0.0/8'
    #line 419 -  uncomment
    'save and exit'

# start and enable postfix
systemctl start postfix
systemctl enable postfix
systemctl status postfix

# create new user
useradd <username>
passwd <username>
cat /etc/passwd | grep <username> #confirm creation
ll /home/<username>

#validate postfix functionality using telnet
telnet stmail01 25
EHLO localhost
mail from:<username>@stratos.xfusioncorp.com
rcpt to:<username>@stratos.xfusioncorp.com
DATA
'test mail'
.

#confirm if the mail is received or queued

su - <username>
cd Maildir/
cat new/

#install dovecot
sudo -i
yum install dovecot -y

#configure dovecot
vi /etc/dovecot/dovecot.conf
    :set nu
    #line 24 - uncomment
    #save and exit
vi /etc/dovecot/conf.d/10-mail.conf
    :set nu
    #line 24 - uncomment
    #save and exit
vi /etc/dovecot/conf.d/10-auth.conf
    :set nu
    #line 10 - uncomment
    #line 100 - uncomment
    'auth_mechanisms = plain login'
     #save and exit
vi /etc/dovecot/conf.d/10-master.conf
    :set nu
    #line 91,92 - uncomment
    'user = postfix
    group = postfix'
    #save and exit

# start and enable dovecot
systemctl start dovecot
systemctl enable dovecot
systemctl status dovecot

#validate dovecot with telnet
telnet stmail01 110
user <username>
pass <password>
retr 1

ss -tulnp

references:
https://www.dell.com/support/kbdoc/en-ca/000129267/how-to-test-an-email-server-with-the-telnet-client


```



The Nautilus application development team has shared that they are planning to deploy one newly developed application on Nautilus infra in Stratos DC. The application uses PostgreSQL database, so as a pre-requisite we need to set up PostgreSQL database server as per requirements shared below:

a. Install and configure PostgreSQL database on Nautilus database server.

b. Create a database user kodekloud_gem and set its password to defaultpassword.

c. Create a database kodekloud_db4 and grant full permissions to user kodekloud_top on this database.

d. Make appropriate settings to allow all local clients (local socket connections) to connect to the kodekloud_db4 database through kodekloud_top user using md5 method (Please do not try to encrypt password with md5sum).

e. At the end its good to test the db connection using these new credentials from root user or server's sudo user.


# DEVOPS TASKS

<br>

> TS(202209260935)

### **ANSIBLE COPY MODULE**

TASK:
<blockquote>
There is data on jump host that needs to be copied on all application servers in Stratos DC. Nautilus DevOps team want to perform this task using Ansible. Perform the task as per details mentioned below:

a. On jump host create an inventory file /home/thor/ansible/inventory and add all application servers as managed nodes.

b. On jump host create a playbook /home/thor/ansible/playbook.yml to copy /usr/src/data/index.html file to all application servers at location /opt/data.

Note: Validation will try to run the playbook using command ansible-playbook -i inventory playbook.yml so please make sure the playbook works this way without passing any extra arguments.
</blockquote>

SOLUTION:
```bash
cd  /home/thor/ansible/ && ll
vi inventory #creates an inventory file 
'stapp01 ansible_host=172.16.238.10 ansible_ssh_pass=defaultpassword  ansible_user=tony

stapp02 ansible_host=172.16.238.11 ansible_ssh_pass=defaultpassword  ansible_user=steve

stapp03 ansible_host=172.16.238.12 ansible_ssh_pass=defaultpassword  ansible_user=banner'

ansible all -a "ls -ltr /opt/data" -i inventory
vi playbook.yml #creates the playbook containing required actions
'- name: Ansible copy
hosts: all
become: yes
tasks:
    - name: copy index.html to data folder
    copy: src=/usr/src/data/index.html dest=/opt/data'

ansible-playbook -i inventory playbook.yml # executes the actions in the playbook
ansible all -a "ls -ltr /opt/data" -i inventory # checks the results of the actions performed by ansible
```

<br>

> TS(202209271930)

### **Deploy Grafana on Kubernetes Cluster**
TASK:
<blockquote>
The Nautilus DevOps teams is planning to set up a Grafana tool to collect and analyze analytics from some applications. They are planning to deploy it on Kubernetes cluster. Below you can find more details.

1.) Create a deployment named grafana-deployment-datacenter using any grafana image for Grafana app. Set other parameters as per your choice.

2.) Create NodePort type service with nodePort 32000 to expose the app.

You need not to make any configuration changes inside the Grafana app once deployed, just make sure you are able to access the Grafana login page.

Note: The kubeclt on jump_host has been configured to work with kubernetes cluster.
</blockquote>

SOLUTION:
```bash
kubectl get pods
kubectl get services
vi /tmp/grafana.yaml
'
apiVersion: v1
kind: Service
metadata:
  name: grafana-service-nautilus
spec:
  type: NodePort
  selector:
    app: grafana
  ports:
    - port: 3000
      targetPort: 3000
      nodePort: 32000
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: grafana-deployment-datacenter
spec:
  selector:
    matchLabels:
      app: grafana
  template:
    metadata:
      labels:
        app: grafana
    spec:
      containers:
        - name: grafana-container-nautilus
          image: grafana/grafana:latest
          ports:
            - containerPort: 3000
'
kubectl create -f /tmp/grafana.yaml
kubectl get service
kubectl get pods

```

<br>

> TS(202209291040)

### **Docker Volumes Mapping**
TASK:
<blockquote>
The Nautilus DevOps team is testing applications containerization, which issupposed to be migrated on docker container-based environments soon. In today's stand-up meeting one of the team members has been assigned a task to create and test a docker container with certain requirements. Below are more details:

a. On App Server 3 in Stratos DC pull nginx image (preferably latest tag but others should work too).
b. Create a new container with name cluster from the image you just pulled.
c. Map the host volume /opt/sysops with container volume /home. There is an sample.txt file present on same server under /tmp; copy that file to /opt/sysops. Also please keep the container in running state.
</blockquote>

SOLUTION:
```bash
#login
ssh banner@stapp03
sudo -i

#docker image
docker images
docker pull nginx:latest

#copy txt file 
cp /tmp/sample.txt /opt/sysops

#run docker image
docker run --name cluster -v /opt/sysops:/home -d -it  nginx:latest

#log in to container
docker ps
docker exec -it <container id>  /bin/bash
ll /home
```

<br>

> TS(202210010800)

### **Git Manage Remotes**
TASK:
<blockquote>
The xFusionCorp development team added updates to the project that is maintained under /opt/media.git repo and cloned under /usr/src/kodekloudrepos/media. Recently some changes were made on Git server that is hosted on Storage server in Stratos DC. The DevOps team added some new Git remotes, so we need to update remote on /usr/src/kodekloudrepos/media repository as per details mentioned below:

a. In /usr/src/kodekloudrepos/media repo add a new remote dev_media and point it to /opt/xfusioncorp_media.git repository.

b. There is a file /tmp/index.html on same server; copy this file to the repo and add/commit to master branch.

c. Finally push master branch to this new remote origin.
</blockquote>

SOLUTION:
```bash
# login
ssh natasha@ststor01
Bl@kW
sudo su -

# move to cloned directory
cd /usr/src/kodekloudrepos/media
ll

# add remote repo
git remote add dev_media /opt/xfusioncorp_media.git

# Copy HTML file from tmp to repo and add
cp /tmp/index.html .

# Git initialize the new remote repo 
git init

# Add and commit the index.html file 
git add index.html
git commit -m "add index.html"

# Push the master branch to new remote origin
git push -u dev_media  master
```

<br>

> TS(202210022030)

### **Create Deployments in Kubernetes Cluster**
TASK:
<blockquote>
The Nautilus DevOps team has started practicing some pods, and services deployment on Kubernetes platform, as they are planning to migrate most of their applications on Kubernetes. Recently one of the team members has been assigned a task to create a deploymnt as per details mentioned below:

Create a deployment named nginx to deploy the application nginx using the image nginx:latest (remember to mention the tag as well)

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster.
</blockquote>

SOLUTION:
```bash
# check for existing deployments and namespaces
kubectl get deploy
kubectl get namespace

# create the nginx deploy and run the image
kubectl create deploy nginx --image nginx:latest

# validate the deployment, pod and instance
kubectl get deploy
kubectl get pods
kubectl describe pod nginx-55649fd747-vq6fj
```

<br>

> TS(202210071900)

### **Puppet Setup NTP Server**
TASK:
<blockquote>
While troubleshooting one of the issues on app servers in Stratos Datacenter DevOps team identified the root cause that the time isn't synchronized properly among the all app servers which causes issues sometimes. So team has decided to use a specific time server for all app servers, so that they all remain in sync. This task needs to be done using Puppet so as per details mentioned below please compete the task:

Create a puppet programming file beta.pp under /etc/puppetlabs/code/environments/production/manifests directory on puppet master node i.e on Jump Server. Within the programming file define a custom class ntpconfig to install and configure ntp server on app server 1.

Add NTP Server server 2.north-america.pool.ntp.org in default configuration file on app server 1, also remember to use iburst option for faster synchronization at startup.

Please note that do not try to start/restart/stop ntp service, as we already have a scheduled restart for this service tonight and we don't want these changes to be applied right now.

Notes: :- Please make sure to run the puppet agent test using sudo on agent nodes, otherwise you can face certificate issues. In that case you will have to clean the certificates first and then you will be able to run the puppet agent test.

:- Before clicking on the Check button please make sure to verify puppet server and puppet agent services are up and running on the respective servers, also please make sure to run puppet agent test to apply/test the changes manually first.

:- Please note that once lab is loaded, the puppet server service should start automatically on puppet master server, however it can take upto 2-3 minutes to start.
</blockquote>

SOLUTION:
```bash
# list existing modules, then install NTP module on jump server
puppet module list
puppet module install puppetlabs-ntp
puppet module list

# cd to the specified filder to create the required puppet file
cd /etc/puppetlabs/code/environments/production/manifests/
ll
vi beta.pp
"
class { 'ntp':
  servers => [ 'server 2.north-america.pool.ntp.org iburst' ],                                               
}    

class ntpconfig {
  include ntp
}  

node 'stapp01.stratos.xfusioncorp.com' {
  include ntpconfig
}
"
cat beta.pp

#validate the puppet file
puppet parser validate beta.pp

#switch to the respective app servers, then run puppet agent to pull the configuration from puppet server
ssh tony@stapp01
sudo -i

puppet resource service ntpd
puppet agent -tv
puppet resource service ntpd

```

<br>

> TS(202210091500)

### **Puppet Install a Package**
TASK:
<blockquote>
Some new packages need to be installed on app server 3 in Stratos Datacenter. The Nautilus DevOps team has decided to install the same using Puppet. Since jump host is already configured to run as Puppet master server and all app servers are already configured to work as the puppet agent nodes, we need to create required manifests on the Puppet master server so that the same can be applied on all Puppet agent nodes. Please find more details about the task below.

Create a Puppet programming file media.pp under /etc/puppetlabs/code/environments/production/manifests directory on master node i.e Jump Server and using puppet package resource perform the tasks given below.

Install package nginx through Puppet package resource only on App server 3 i.e puppet agent node 3`.
Notes: :- Please make sure to run the puppet agent test using sudo on agent nodes, otherwise you can face certificate issues. In that case you will have to clean the certificates first and then you will be able to run the puppet agent test.

:- Before clicking on the Check button please make sure to verify puppet server and puppet agent services are up and running on the respective servers, also please make sure to run puppet agent test to apply/test the changes manually first.

:- Please note that once lab is loaded, the puppet server service should start automatically on puppet master server, however it can take upto 2-3 minutes to start.
</blockquote>
SOLUTION:

```bash
# switch to root and cd designated folder and create puppet file
sudo -i
cd /etc/puppetlabs/code/environments/production/manifests
vi media.pp
'
class nginx_installer {
  package {'nginx':
    ensure => installed
  }
}

node 'stapp03.stratos.xfusioncorp.com' {
  include nginx_installer
}
'
# validate the puppet command
puppet parser validate media.pp

# login to the app server
ssh banner@stapp03
sudo -i

# pull the configuration from puppet server by running the puppet agent
puppet agent -tv

# validate the package installation
rpm -aq | grep nginx
```
<br>

> TS(202210101800)

### **Setup Puppet Certs Autosign**
TASK:
<blockquote>
During last weekly meeting, the Nautilus DevOps team has decided to use Puppet autosign config to auto sign the certificates for all Puppet agent nodes that they will keep adding under the Puppet master in Stratos DC. The Puppet master and CA servers are currently running on jump host and all three app servers are configured as Puppet agents. To set up autosign configuration on the Puppet master server, some configuration settings must be done. Please find below more details:

The Puppet server package is already installed on puppet master i.e jump server and the Puppet agent package is already installed on all App Servers. However, you may need to start the required services on all of these servers.

Configure autosign configuration on the Puppet master i.e jump server (by creating an autosign.conf in the puppet configuration directory) and assign the certificates for master node as well as for the all agent nodes. Use the respective host's FDQN to assign the certificates.

Use alias puppet (dns_alt_names) for master node and add its entry in /etc/hosts config file on master i.e Jump Server as well as on the all agent nodes i.e App Servers.

Notes: :- Please make sure to run the puppet agent test using sudo on agent nodes, otherwise you can face certificate issues. In that case you will have to clean the certificates first and then you will be able to run the puppet agent test.

:- Before clicking on the Check button please make sure to verify puppet server and puppet agent services are up and running on the respective servers, also please make sure to run puppet agent test to apply/test the changes manually first.

:- Please note that once lab is loaded, the puppet server service should start automatically on puppet master server, however it can take upto 2-3 minutes to start.
</blockquote>
SOLUTION:

```bash
#
sudo -i
cat /etc/hosts
ping puppet
vi /etc/hosts
'
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.16.238.10   stapp01.stratos.xfusioncorp.com
172.16.238.11   stapp02.stratos.xfusioncorp.com
172.16.238.12   stapp03.stratos.xfusioncorp.com
172.16.238.3    jump_host.stratos.xfusioncorp.com jump_host puppet
172.16.239.4    jump_host.stratos.xfusioncorp.com jump_host
'
ping puppet

# Create autosign config file & define all App server FQDN
vi /etc/puppetlabs/puppet/autosign.conf
'
jump_host.stratos.xfusioncorp.com
stapp01.stratos.xfusioncorp.com
stapp02.stratos.xfusioncorp.com
stapp03.stratos.xfusioncorp.com
'
# Post file saved restart the puppetserver daemon
systemctl restart puppetserver
systemctl status puppetserver

# Check any certificate exist on puppet server
puppetserver ca list --all

# Now login on all app server stapp01, stapp02 & stapp03 and Switch to  root user 

ssh tony@stapp01
sudo -i

# Edit Hosts file and add the puppet server ( Jumpserver )  & on App Server 
vi /etc/hosts
'
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.16.238.10   stapp01.stratos.xfusioncorp.com stapp01
172.16.239.3    stapp01.stratos.xfusioncorp.com stapp01
172.16.238.3    jump_host.stratos.xfusioncorp.com jump_host puppet
172.16.239.4    jump_host.stratos.xfusioncorp.com jump_host
'
ping puppet

# Restart the  puppet service on App server  
systemctl restart puppet
systemctl status puppet

# Validate by running the puppet agent 
puppet agent -tv

# List the certificate auto signed on puppet server (jumpserver)
puppetserver ca list --all

```
<br>

> TS(202210132200)

### **Update an Existing Deployment in Kubernetes**
TASK:
<blockquote>
There is an application deployed on Kubernetes cluster. Recently, the Nautilus application development team developed a new version of the application that needs to be deployed now. As per new updates some new changes need to be made in this existing setup. So update the deployment and service as per details mentioned below:

We already have a deployment named nginx-deployment and service named nginx-service. Some changes need to be made in this deployment and service, make sure not to delete the deployment and service.

1.) Change the service nodeport from 30008 to 32165
2.) Change the replicas count from 1 to 5
3.) Change the image from nginx:1.19 to nginx:latest

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster.
</blockquote>
SOLUTION:

```bash

kubectl get deploy
kubectl get service
kubectl get pods
kubectl edit service nginx-service
kubectl get service
kubectl get deploy
kubectl get pods
kubectl edit service nginx-service
kubectl get service
kubectl edit deploy nginx-deployment
kubectl get pods
kubectl get deploy
kubectl get pods

```
<br>

> TS(202210220130)

### **Docker Copy Operations**
TASK:
<blockquote>
The Nautilus DevOps team has some conditional data present on App Server 2 in Stratos Datacenter. There is a container ubuntu_latest running on the same server. We received a request to copy some of the data from the docker host to the container. Below are more details about the task:

On App Server 2 in Stratos Datacenter copy an encrypted file /tmp/nautilus.txt.gpg from docker host to ubuntu_latest container (running on same server) in /usr/src/ location. Please do not try to modify this file in any way.
</blockquote>
SOLUTION:

```bash
# ssh into application server and switch to root user
ssh steve@stapp02
sudo -i

# show running containers
docker ps

# copy file from host to container
docker cp /tmp/nautilus.txt.gpg ubuntu_latest:/usr/src

# validate the copy operation by listing files in the destination folder on the container
docker exec ubuntu_latest ls -lrt /usr/src
```
<br>

> TS(202210260450)

### **Puppet Setup SSH Keys**
TASK:
<blockquote>
The Puppet master and Puppet agent nodes have been set up by the Nautilus DevOps team to perform some testing. In Stratos DC all app servers have been configured as Puppet agent nodes. They want to setup a password less SSH connection between Puppet master and Puppet agent nodes and this task needs to be done using Puppet itself. Below are details about the task:

Create a Puppet programming file news.pp under /etc/puppetlabs/code/environments/production/manifests directory on the Puppet master node i.e on Jump Server. Define a class ssh_node1 for agent node 1 i.e App Server 1, ssh_node2 for agent node 2 i.e App Server 2, ssh_node3 for agent node3 i.e App Server 3. You will need to generate a new ssh key for thor user on Jump Server, that needs to be added on all App Servers.

Configure a password less SSH connection from puppet master i.e jump host to all App Servers. However, please make sure the key is added to the authorized_keys file of each app's sudo user (i.e tony for App Server 1).
</blockquote>

SOLUTION:

```bash
# generate SSH key for user thor and copy the public key to the clipboard
ssh-keygen -t rsa
cat  /root/.ssh/id_rsa.pub

# switch to root user and create the puppet file in the specified folder
sudo -i
cd /etc/puppetlabs/code/environments/production/manifests
vi news.pp
'
$public_key =  'AAAAB3NzaC1yc2EAAAADAQABAAABAQCiuZvnzFZ/+yPxF1ayGXo855YIf+gKjfDWX9Ja/CdFDB6pXo1bRuIuO4GclP7zY3uPxLm54nSZRv7wRPGQSI/qaaYreMZEtR2UpJ+uZIiwONFQJHDd+hKGMB/lBuhbjPI1vHMztISef8ZaikrXNn4eQuNJb22sSl4JWaIxQFwMuhOcSKxRKi3Ld1VDXkQid5XT89u4kD1BcDqAlg1clpH49naGVzwLH65b+8xK2/UdUwA3u93/jEcz7JT3ig3KDlqhRo1+xBOwizJRjTYEpdpTrVQFIcfFgUEBAYGSXOLr3iqsTfbrwCK/R/YMGdv6sUkJUBiIBTtnK5l2/wsRf5RF'

class ssh_node1 {
   ssh_authorized_key { 'tony@stapp01':
     ensure => present,
     user   => 'tony',
     type   => 'ssh-rsa',
     key    => $public_key,
   }
 }
 class ssh_node2 {
   ssh_authorized_key { 'steve@stapp02':
     ensure => present,
     user   => 'steve',
     type   => 'ssh-rsa',
     key    => $public_key,
   }
 }
 class ssh_node3 {
   ssh_authorized_key { 'banner@stapp03':
     ensure => present,
     user   => 'banner',
     type   => 'ssh-rsa',
     key    => $public_key,
   }
 }
 node stapp01.stratos.xfusioncorp.com {
   include ssh_node1
 }
 node stapp02.stratos.xfusioncorp.com {
   include ssh_node2
 }
 node stapp03.stratos.xfusioncorp.com {
   include ssh_node3
 }
'

# validate the puppet file created
puppet parser validate demo.pp

# login to the respective puppet agent servers and switch to root user
ssh user@host

# pull in the puppet configuration from the puppet master
puppet agent -tv

# log out and validate the task via ssh login without password
ssh user@host
```
<br>

> TS(202210311320)

### **Create Pods in Kubernetes Cluster**
TASK:
<blockquote>
The Nautilus DevOps team has started practicing some pods and services deployment on Kubernetes platform as they are planning to migrate most of their applications on Kubernetes platform. Recently one of the team members has been assigned a task to create a pod as per details mentioned below:

Create a pod named pod-httpd using httpd image with latest tag only and remember to mention the tag i.e httpd:latest.

Labels app should be set to httpd_app, also container should be named as httpd-container.

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster.
</blockquote>

SOLUTION:

```bash

# confirm the kubectl utility is functional by reading the namespace
kubectl get namespace

# check for any available pods
kubectl get pods

# create yaml file with the required parameters
vi /tmp/pod.yaml
'
apiVersion: v1

kind: Pod

metadata:
    name: pod-httpd
    labels:
      app: httpd_app

spec:
    containers:
    - name: httpd-container
      image: httpd:latest
'

# create the pod
kubectl create -f /tmp/pod.yaml

# validate
kubectl get pods -o wide
```
<br>

> TS(202210311320)

### **Create Docker Network**
TASK:
<blockquote>
The Nautilus DevOps team needs to set up several docker environments for different applications. One of the team members has been assigned a ticket where he has been asked to create some docker networks to be used later. Complete the task based on the following ticket description:

a. Create a docker network named as ecommerce on App Server 2 in Stratos DC.

b. Configure it to use macvlan drivers.

c. Set it to use subnet 172.168.0.0/24 and iprange 172.168.0.2/24.
</blockquote>

SOLUTION:

```bash
# check for existing docker networks
docker network ls

# create a docker network with the following parameters
docker network create -d macvlan --subnet=172.168.0.0/24 --ip-range=172.168.0.2/24 ecommerce

# validate the result
docker network ls

docker network inspect ecommerce
```
<br>

> TS(202211230110)

### **Manage Secrets in Kubernetes**
TASK:
<blockquote>
The Nautilus DevOps team is working to deploy some tools in Kubernetes cluster. Some of the tools are licence based so that licence information needs to be stored securely within Kubernetes cluster. Therefore, the team wants to utilize Kubernetes secrets to store those secrets. Below you can find more details about the requirements:

We already have a secret key file ecommerce.txt under /opt location on jump host. Create a generic secret named ecommerce, it should contain the password/license-number present in ecommerce.txt file.

Also create a pod named secret-devops.

Configure pod's spec as container name should be secret-container-devops, image should be fedora preferably with latest tag (remember to mention the tag with image). Use sleep command for container so that it remains in running state. Consume the created secret and mount it under /opt/demo within the container.

To verify you can exec into the container secret-container-devops, to check the secret key under the mounted path /opt/demo. Before hitting the Check button please make sure pod/pods are in running state, also validation can take some time to complete so keep patience.

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster.
</blockquote>

SOLUTION:

```bash
#confirm secrets file exists
ll /opt/

# create the secret
kubectl create secret generic ecommerce --from-file='/opt/ecommerce.txt'

# create yaml configuration file
vi /tmp/secret.yml
'
apiVersion: v1
kind: Pod
metadata:
  name: secret-devops
  labels:
    name: myapp

spec:
  volumes:
    - name: secret-volume-devops
      secret:
        secretName: ecommerce
  containers:
    - name: secret-container-devops
      image: fedora:latest
      command: ["/bin/bash", "-c", "sleep 10000"]
      volumeMounts:
        - name: secret-volume-devops
          mountPath: /opt/demo
'

# create a pod from the yaml parameters file
kubectl create -f /tmp/secret.yml

#confirm running status of pods
kubectl get pods

#validate secret has been correctly configured
kubectl exec secret-devops -- cat /opt/demo/ecommerce.txt
```
<br>

> TS(202211270110)

### **Puppet string manipulation**
TASK:
<blockquote>
There is some data on App Server 3 in Stratos DC. The Nautilus development team shared some requirement with the DevOps team to alter some of the data as per recent changes. The DevOps team is working to prepare a Puppet programming file to accomplish this. Below you can find more details about the task.


Create a Puppet programming file cluster.pp under /etc/puppetlabs/code/environments/production/manifests directory on Puppet master node i.e Jump Server and by using puppet file_line resource perform the following tasks.

We have a file /opt/dba/cluster.txt on App Server 3. Use the Puppet programming file mentioned above to replace line Welcome to Nautilus Industries! to Welcome to xFusionCorp Industries!, no other data should be altered in this file.
Notes: :- Please make sure to run the puppet agent test using sudo on agent nodes, otherwise you can face certificate issues. In that case you will have to clean the certificates first and then you will be able to run the puppet agent test.

</blockquote>

SOLUTION:

```bash
# create the puppet programming file
vi cluster.pp
'
class data_replacer {
  file_line { 'line_replace':
    path => '/opt/dba/cluster.txt',
    match => 'Welcome to Nautilus Industries!',
    line  => 'Welcome to xFusionCorp Industries!',
  }
}
node 'stapp03.stratos.xfusioncorp.com' {
  include data_replacer
}
'
# validate the file
puppet parser validate cluster.pp

# log in to the app server and switch to root user

# Run the puppet agent to pull the configuration from the puppet server

puppet agent -tv

# validate the task
cat /opt/dba/cluster.txt
```
<br>

> TS(202212040725)

### **Create Namespaces in Kubernetes Cluster**
TASK:
<blockquote>
The Nautilus DevOps team is planning to deploy some micro services on Kubernetes platform. The team has already set up a Kubernetes cluster and now they want set up some namespaces, deployments etc. Based on the current requirements, the team has shared some details as below:

Create a namespace named dev and create a POD under it; name the pod dev-nginx-pod and use nginx image with latest tag only and remember to mention tag i.e nginx:latest.

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster.
</blockquote>
SOLUTION:

```bash

kubectl create namespace dev

kubectl run dev-nginx-pod --image=nginx:latest -n dev


```
<br>

> TS(202212111725)

### **Fix Issue with VolumeMounts in Kubernetes**
TASK:
<blockquote>
We deployed a Nginx and PHPFPM based setup on Kubernetes cluster last week and it had been working fine. This morning one of the team members made a change somewhere which caused some issues, and it stopped working. Please look into the issue and fix it:

The pod name is nginx-phpfpm and configmap name is nginx-config. Figure out the issue and fix the same.
Once issue is fixed, copy /home/thor/index.php file from jump host into nginx-container under nginx document root and you should be able to access the website using Website button on top bar.

Note: The kubectl utility on jump_host has been configured to work with the kubernetes cluster. 
</blockquote>
SOLUTION:

```bash

# check existing running pods
kubectl get pods

# check shared volume path
kubectl get configmap
kubectl describe configmap nginx-config

# get the configuration in the YAML file from the running pod
kubectl get pod nginx-phpfpm -o yaml > /tmp/nginx.yaml
ll /tmp/
cat /tmp/nginx.yaml

# edit the nginx.yaml file by changing every occurrence of 'usr/share/nginx/html' to '/var/www/html' -> the shared volume path
cat /tmp/nginx.yaml |grep /usr/share/nginx/html

# post the changes to the running pod
kubectl replace -f /tmp/nginx.yaml --force

# confirm pod is running
kubectl get pods

# copy index.php file as required
kubectl cp /home/thor/index.php nginx-phpfpm:/var/www/html -c nginx-container

# validate task: curl the nginx port
kubectl exec -it nginx-phpfpm -c nginx-container --curl -l http://localhost:8099
```

