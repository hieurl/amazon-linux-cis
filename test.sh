#! /bin/bash

. lib.sh
TITLE "1. Intial setup"
TITLE "1.1 Filesystem Configuration"
TITLE "1.1.1.1 Ensure mounting of cramfs filesystems is disabled"
_test_mod_disabled cramfs
TITLE "1.1.1.2 Ensure mounting of freevxfs filesystems is disabled"
_test_mod_disabled freevxfs
TITLE "1.1.1.3 Ensure mounting of jffs2 filesystems is disabled"
_test_mod_disabled jffs2
TITLE "1.1.1.4 Ensure mounting of hfs filesystems is disabled"
_test_mod_disabled hfs
TITLE "1.1.1.5 Ensure mounting of hfsplus filesystems is disabled"
_test_mod_disabled hfsplus
TITLE "1.1.1.6 Ensure mounting of squashfs filesystems is disabled"
_test_mod_disabled squashfs
TITLE "1.1.1.7 Ensure mounting of udf filesystems is disabled"
_test_mod_disabled udf
TITLE "1.1.1.8 Ensure mounting of FAT filesystems is disabled"
_test_mod_disabled vfat

TITLE "1.1.2 Ensure separate partition exists for /tmp"
_test_fs_mounted /tmp
TITLE "1.1.3 Ensure nodev option set on /tmp partition"
_test_fs_option_set /tmp nodev
TITLE "1.1.4 Ensure nosuid option set on /tmp partition"
_test_fs_option_set /tmp nosuid
TITLE "1.1.5 Ensure noexec option set on /tmp partition"
_test_fs_option_set /tmp noexec

TITLE "1.1.6 Ensure separate partition exists for /var"
_test_fs_mounted /var
TITLE "1.1.7 Ensure separate partition exists for /var/tmp"
_test_fs_mounted /var/tmp
TITLE "1.1.8 Ensure nodev option set on /var/tmp partition"
_test_fs_option_set /var/tmp nodev
TITLE "1.1.9 Ensure nosuid option set on /var/tmp partition"
_test_fs_option_set /var/tmp nosuid
TITLE "1.1.10 Ensure noexec option set on /var/tmp partition"
_test_fs_option_set /var/tmp noexec
TITLE "1.1.11 Ensure separate partition exists for /var/log"
_test_fs_mounted /var/log
TITLE "1.1.12 Ensure separate partition exists for /var/log/audit"
_test_fs_mounted /var/log/audit

TITLE "1.1.13 Ensure separate partition exists for /home"
_test_fs_mounted /home
TITLE "1.1.14 Ensure nodev option set on /home partition"
_test_fs_option_set /home nodev


TITLE "1.1.15 Ensure nodev option set on /dev/shm partition"
_test_fs_option_set /dev/shm nodev
TITLE "1.1.16 Ensure nosuid option set on /dev/shm partition"
_test_fs_option_set /dev/shm nosuid
TITLE "1.1.17 Ensure noexec option set on /dev/shm partition"
_test_fs_option_set /dev/shm noexec

TITLE "1.1.18 Ensure sticky bit is set on all world-writable directories"
_test_list_sticky_bit
TITLE "1.1.19 Disable Automounting"
_test_chkconfig_disabled autofs

TITLE "1.2.3 Ensure gpgcheck is globally activated"
_test_gpgcheck_enable

TITLE "1.3.1 Ensure AIDE is installed"
_test_aide_present
TITLE "1.3.2 Ensure filesystem integrity is regularly checked"
_test_aide_cron_configured
TITLE "1.4.1 Ensure permissions on bootloader config are configured"
_test_file_permission /boot/grub/menu.lst 0600
TITLE "1.4.2 Ensure authentication required for single user mode"
_test_auth_for_single_user_mode
TITLE "1.4.3 Ensure interactive boot is not enabled"
_test_interactive_boot

TITLE "1.5.1 Ensure core dumps are restricted"
_test_coredump_restrict
TITLE "1.5.2 Ensure XD/NX support is enabled"
_test_xdnx_enabled
TITLE "1.5.3 Ensure address space layout randomization (ASLR) is enabled"
_test_aslr_enabled
TITLE "1.5.4 Ensure prelink is disabled"
_test_package_removed prelink

TITLE "1.6.1.1 Ensure SELinux is not disabled in bootloader configuration"
_test_selinux_enabled

TITLE "1.6.1.2 Ensure the SELinux state is enforcing"
_test_selinux_enforced

TITLE "1.6.1.3 Ensure SELinux policy is configured"
_test_selinux_config

TITLE "1.6.1.4 Ensure SETroubleshoot is not installed"
_test_package_removed setroubleshoot

TITLE "1.6.1.5 Ensure the MCS Translation Service (mcstrans) is not installed"
_test_package_removed mcstrans

TITLE "1.6.1.6 Ensure no unconfined daemons exist"
_test_unconfined_daemons

TITLE "1.6.2 Ensure SELinux is installed"
_test_package_installed libselinux

TITLE "1.7.1 Ensure message of the day is configured properly"
_test_motd

TITLE "1.7.1.5 Ensure permissions on /etc/issue are configured"
_test_file_permission /etc/issue 0644
TITLE "1.7.1.6 Ensure permissions on /etc/issue.net are configured"
_test_file_permission /etc/issue.net 0644


TITLE "2.1.1 Ensure chargen services are not enabled"
_test_chkconfig_disabled chargen
TITLE "2.1.2 Ensure daytime services are not enabled"
_test_chkconfig_disabled daytime
TITLE "2.1.3 Ensure discard services are not enabled"
_test_chkconfig_disabled discard
TITLE "2.1.4 Ensure echo services are not enabled"
_test_chkconfig_disabled echo
TITLE "2.1.5 Ensure time services are not enabled"
_test_chkconfig_disabled time
TITLE "2.1.6 Ensure rsh server is not enabled"
_test_chkconfig_disabled rsh
_test_chkconfig_disabled rlogin
_test_chkconfig_disabled rexec
TITLE "2.1.7 Ensure talk server is not enabled"
_test_chkconfig_disabled talk
TITLE "2.1.8 Ensure telnet server is not enabled"
_test_chkconfig_disabled telnet
TITLE "2.1.9 Ensure tftp server is not enabled"
_test_chkconfig_disabled tftp
TITLE "2.1.10 Ensure rsync service is not enabled"
_test_chkconfig_disabled rsync
TITLE "2.1.11 Ensure xinetd is not enabled"
_test_chkconfig_disabled xinetd
TITLE "2.2.1.1 Ensure time synchronization is in use"
_test_package_installed ntp
_test_package_installed chrony
TITLE "2.2.1.2 Ensure ntp is configured"
_test_ntp_conf
TITLE "2.2.1.3 Ensure chrony is configured"
_test_chrony_conf
TITLE "2.2.2 Ensure X Window System is not installed"
_test_package_group_removed "xorg-x11"
TITLE "2.2.3 Ensure Avahi Server is not enabled"
_test_chkconfig_disabled avahi-daemon
TITLE "2.2.4 Ensure CUPS is not enabled"
_test_chkconfig_disabled cups
TITLE "2.2.5 Ensure DHCP Server is not enabled"
_test_chkconfig_disabled dhcpd
TITLE "2.2.6 Ensure LDAP server is not enabled"
_test_chkconfig_disabled slapd
TITLE "2.2.7 Ensure NFS and RPC are not enabled"
_test_chkconfig_disabled nfs
_test_chkconfig_disabled rpcbind
TITLE "2.2.8 Ensure DNS Server is not enabled"
_test_chkconfig_disabled named
TITLE "2.2.9 Ensure FTP Server is not enabled"
_test_chkconfig_disabled vsftpd
TITLE "2.2.10 Ensure HTTP server is not enabled"
_test_chkconfig_disabled httpd
TITLE "2.2.11 Ensure IMAP and POP3 server is not enabled"
_test_chkconfig_disabled dovecot
TITLE "2.2.12 Ensure Samba is not enabled"
_test_chkconfig_disabled smb
TITLE "2.2.13 Ensure HTTP Proxy Server is not enabled"
_test_chkconfig_disabled squid
TITLE "2.2.14 Ensure SNMP Server is not enabled"
_test_chkconfig_disabled snmpd
TITLE "2.2.15 Ensure mail transfer agent is configured for local-only mode"
_test_port_listen_local 25
TITLE "2.2.16 Ensure NIS Server is not enabled"
_test_chkconfig_disabled ypserv
TITLE "2.3.1 Ensure NIS Client is not installed"
_test_chkconfig_disabled ypbind
TITLE "2.3.2 Ensure rsh client is not installed"
_test_package_removed rsh
TITLE "2.3.3 Ensure talk client is not installed"
_test_package_removed talk
TITLE "2.3.4 Ensure telnet client is not installed"
_test_package_removed telnet
TITLE "2.3.5 Ensure LDAP client is not installed"
_test_package_removed openldap-clients
TITLE "3.1 Network Parameters"
TITLE "3.1.1 Ensure IP forwarding is disabled"
_test_sysctl_equal net.ipv4.ip_forward 0
TITLE "3.1.2 Ensure packet redirect sending is disabled"
_test_sysctl_equal net.ipv4.conf.all.send_redirects 0
_test_sysctl_equal net.ipv4.conf.default.send_redirects 0
TITLE "3.2 Network Parameters"
TITLE "3.2.1 Ensure source routed packets are not accepted"
_test_sysctl_equal net.ipv4.conf.all.accept_source_route 0
_test_sysctl_equal net.ipv4.conf.default.accept_source_route 0
TITLE "3.2.2 Ensure ICMP redirects are not accepted"
_test_sysctl_equal net.ipv4.conf.all.accept_redirects 0
_test_sysctl_equal net.ipv4.conf.default.accept_redirects 0
TITLE "3.2.3 Ensure secure ICMP redirects are not accepted"
_test_sysctl_equal net.ipv4.conf.all.secure_redirects 0
_test_sysctl_equal net.ipv4.conf.default.secure_redirects 0
TITLE "3.2.4 Ensure suspicious packets are logged"
_test_sysctl_equal net.ipv4.conf.all.log_martians 1
_test_sysctl_equal net.ipv4.conf.default.log_martians 1
TITLE "3.2.5 Ensure broadcast ICMP requests are ignored"
_test_sysctl_equal net.ipv4.icmp_echo_ignore_broadcasts 1
TITLE "3.2.6 Ensure bogus ICMP responses are ignored"
_test_sysctl_equal net.ipv4.icmp_ignore_bogus_error_responses 1
TITLE "3.2.7 Ensure Reverse Path Filtering is enabled"
_test_sysctl_equal net.ipv4.conf.all.rp_filter 1
_test_sysctl_equal net.ipv4.conf.default.rp_filter 1
TITLE "3.2.8 Ensure TCP SYN Cookies is enabled"
_test_sysctl_equal net.ipv4.tcp_syncookies 1
TITLE "3.3.1 Ensure IPv6 router advertisements are not accepted"
_test_sysctl_equal net.ipv6.conf.all.accept_ra 0
_test_sysctl_equal net.ipv6.conf.default.accept_ra 0
TITLE "3.3.2 Ensure IPv6 redirects are not accepted"
_test_sysctl_equal net.ipv6.conf.all.accept_redirects 0
_test_sysctl_equal net.ipv6.conf.default.accept_redirects 0
TITLE "3.3.3 Ensure IPv6 is disabled"
TITLE "3.4.1 Ensure TCP Wrappers is installed"
_test_package_installed tcp_wrappers
_test_package_installed tcp_wrappers-libs
TITLE "3.4.2 Ensure /etc/hosts.allow is configured"
cat /etc/hosts.allow
FAILED "not configured"
TITLE "3.4.3 Ensure /etc/hosts.deny is configured"
cat /etc/hosts.deny
FAILED "not configured"
TITLE "3.4.4 Ensure permissions on /etc/hosts.allow are configured"
_test_file_permission /etc/hosts.allow 0644
TITLE "3.4.5 Ensure permissions on /etc/hosts.deny are configured"
_test_file_permission /etc/hosts.deny 0644
TITLE "3.5.1 Ensure DCCP is disabled"
_test_mod_disabled dccp
TITLE "3.5.2 Ensure SCTP is disabled"
_test_mod_disabled sctp
TITLE "3.5.3 Ensure RDS is disabled"
_test_mod_disabled rds
TITLE "3.5.4 Ensure TIPC is disabled"
_test_mod_disabled tipc
TITLE "3.6.1 Ensure iptables is installed"
_test_package_installed iptables
TITLE "3.6.2 Ensure default deny firewall policy"
_test_iptables_chain_policy INPUT DROP
_test_iptables_chain_policy FORWARD DROP
_test_iptables_chain_policy OUTPUT DROP
TITLE "3.6.3 Ensure loopback traffic is configured"
_test_iptables_loopback_conf
TITLE "3.6.4 Ensure outbound and established connections are configured"
iptables -L -v -n
PASSED "reviewed"
TITLE "3.6.5 Ensure firewall rules exist for all open ports"
_test_iptables_rules_for_open_port
TITLE "4.1 Configure System Accounting"
TITLE "4.1.1.1 Ensure audit log storage size is configured"
_test_file_contains "max_log_file =" /etc/audit/auditd.conf
TITLE "4.1.1.2 Ensure system is disabled when audit logs are full"
_test_file_contains "space_left_action = " /etc/audit/auditd.conf
_test_file_contains "space_left_action = email" /etc/audit/auditd.conf
_test_file_contains "action_mail_acct = " /etc/audit/auditd.conf
_test_file_contains "action_mail_acct = root" /etc/audit/auditd.conf
_test_file_contains "admin_space_left_action = " /etc/audit/auditd.conf
_test_file_contains "admin_space_left_action = halt" /etc/audit/auditd.conf
TITLE "4.1.1.3 Ensure audit logs are not automatically deleted"
_test_file_contains "max_log_file_action = " /etc/audit/auditd.conf
_test_file_contains "max_log_file_action = keep_logs" /etc/audit/auditd.conf
TITLE "4.1.2 Ensure auditd service is enabled"
_test_chkconfig_enabled auditd
TITLE "4.1.3 Ensure auditing for processes that start prior to auditd is enabled"
_test_file_contains  "^\s*kernel.*audit=1" /boot/grub/menu.lst
TITLE "4.1.4 Ensure events that modify date and time information are collected"
TITLE "4.1.5 Ensure events that modify user/group information are collected"
TITLE "4.1.6 Ensure events that modify the system's network environment are collected"
TITLE "4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected"
TITLE "4.1.8 Ensure login and logout events are collected"
TITLE "4.1.9 Ensure session initiation information is collected"
TITLE "4.1.10 Ensure discretionary access control permission modification events are collected"
TITLE "4.1.11 Ensure unsuccessful unauthorized file access attempts are collected"
TITLE "4.1.12 Ensure use of privileged commands is collected"
TITLE "4.1.13 Ensure successful file system mounts are collected"
TITLE "4.1.14 Ensure file deletion events by users are collected"
TITLE "4.1.15 Ensure changes to system administration scope (sudoers) is collected"
TITLE "4.1.16 Ensure system administrator actions (sudolog) are collected"
TITLE "4.1.17 Ensure kernel module loading and unloading is collected"
TITLE "4.1.18 Ensure the audit configuration is immutable"
set -x
cat /etc/audit/audit.rules
auditctl -l
set +x
PASSED "configured"
TITLE "4.2.1.1 Ensure rsyslog Service is enabled"
_test_chkconfig_enabled rsyslog
TITLE "4.2.1.2 Ensure logging is configured"
PASSED "reviewed"
TITLE "4.2.1.3 Ensure rsyslog default file permissions configured"
_test_file_contains "^.FileCreateMode 0640" /etc/rsyslog.conf
TITLE "4.2.1.4 Ensure rsyslog is configured to send logs to a remote log host"
FAILED "not configured"
TITLE "4.2.1.5 Ensure remote rsyslog messages are only accepted on designated log hosts."
FAILED "not configured"
TITLE "4.2.2.1 Ensure syslog-ng service is enabled"
_test_chkconfig_enabled syslog-ng
TITLE "4.2.2.2 Ensure logging is configured"
FAILED "not configured"
TITLE "4.2.2.3 Ensure syslog-ng default file permissions configured"
FAILED "not configured"
TITLE "4.2.2.4 Ensure syslog-ng is configured to send logs to a remote log host"
FAILED "not configured"
TITLE "4.2.2.5 Ensure remote syslog-ng messages are only accepted on designated log hosts"
FAILED "not configured"
TITLE "4.2.3 Ensure rsyslog or syslog-ng is installed"
_test_package_installed rsyslog
TITLE "4.2.4 Ensure permissions on all logfiles are configured"
_test_directory_file_permission_exclude /var/log "....*w"
TITLE "4.3 Ensure logrotate is configured"
PASSED "reviewed"
TITLE "5.1.1 Ensure cron daemon is enabled"
_test_chkconfig_enabled crond
TITLE "5.1.2 Ensure permissions on /etc/crontab are configured"
_test_file_permission /etc/crontab 0600
TITLE "5.1.3 Ensure permissions on /etc/cron.hourly are configured"
_test_file_permission /etc/cron.hourly 0700
TITLE "5.1.4 Ensure permissions on /etc/cron.daily are configured"
_test_file_permission /etc/cron.daily 0700
TITLE "5.1.5 Ensure permissions on /etc/cron.weekly are configured"
_test_file_permission /etc/cron.weekly 0700
TITLE "5.1.6 Ensure permissions on /etc/cron.monthly are configured"
_test_file_permission /etc/cron.monthly 0700
TITLE "5.1.7 Ensure permissions on /etc/cron.d are configured"
_test_file_permission /etc/cron.d 0700
TITLE "5.1.8 Ensure at/cron is restricted to authorized users"
_test_file_not_exists /etc/cron.deny
_test_file_not_exists /etc/at.deny
_test_file_permission /etc/cron.allow 0600
_test_file_permission /etc/at.allow 0600
TITLE "5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured"
_test_file_permission /etc/ssh/sshd_config 0600
TITLE "5.2.2 Ensure SSH Protocol is set to 2"
_test_file_contains "^Protocol 2" /etc/ssh/sshd_config
TITLE "5.2.3 Ensure SSH LogLevel is set to INFO"
_test_file_contains "^LogLevel INFO" /etc/ssh/sshd_config
TITLE "5.2.4 Ensure SSH X11 forwarding is disabled"
_test_file_contains "^X11Forwarding no" /etc/ssh/sshd_config
TITLE "5.2.5 Ensure SSH MaxAuthTries is set to 4 or less"
_test_file_contains "^MaxAuthTries [1-4]" /etc/ssh/sshd_config
TITLE "5.2.6 Ensure SSH IgnoreRhosts is enabled"
_test_file_contains "^IgnoreRhosts yes" /etc/ssh/sshd_config
TITLE "5.2.7 Ensure SSH HostbasedAuthentication is disabled"
_test_file_contains "^HostbasedAuthentication no" /etc/ssh/sshd_config
TITLE "5.2.8 Ensure SSH root login is disabled"
_test_file_contains "^PermitRootLogin no" /etc/ssh/sshd_config
TITLE "5.2.9 Ensure SSH PermitEmptyPasswords is disabled"
_test_file_contains "^PermitEmptyPasswords no" /etc/ssh/sshd_config
TITLE "5.2.10 Ensure SSH PermitUserEnvironment is disabled"
_test_file_contains "^PermitUserEnvironment no" /etc/ssh/sshd_config
TITLE "5.2.11 Ensure only approved MAC algorithms are used"
_test_file_contains "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" /etc/ssh/sshd_config
TITLE "5.2.12 Ensure SSH Idle Timeout Interval is configured"
_test_file_contains "^ClientAliveInterval 300" /etc/ssh/sshd_config
_test_file_contains "^ClientAliveCountMax [0-3]" /etc/ssh/sshd_config
TITLE "5.2.13 Ensure SSH LoginGraceTime is set to one minute or less"
_test_file_contains "^LoginGraceTime 60" /etc/ssh/sshd_config
TITLE "5.2.14 Ensure SSH access is limited"
_test_file_contains "^AllowUsers ec2-user" /etc/ssh/sshd_config
TITLE "5.2.15 Ensure SSH warning banner is configured"
_test_file_contains "^Banner /etc/issue.net" /etc/ssh/sshd_config
TITLE "5.3.1 Ensure password creation requirements are configured"
_test_file_contains "password\s+requisite\s+pam_pwquality.so try_first_pass local_users_only retry=3" /etc/pam.d/password-auth
_test_file_contains "password\s+requisite\s+pam_pwquality.so try_first_pass local_users_only retry=3" /etc/pam.d/system-auth
_test_file_contains "^minlen\s*=\s*1[4-9]" /etc/security/pwquality.conf
_test_file_contains "^dcredit\s*=\s*\-1" /etc/security/pwquality.conf
_test_file_contains "^lcredit\s*=\s*\-1" /etc/security/pwquality.conf
_test_file_contains "^ocredit\s*=\s*\-1" /etc/security/pwquality.conf
_test_file_contains "^ucredit\s*=\s*\-1" /etc/security/pwquality.conf
TITLE "5.3.2 Ensure lockout for failed password attempts is configured"
_test_file_contains "auth\s+required\s+pam_faillock.so preauth audit silent deny=5 unlock_time=900" /etc/pam.d/password-auth
_test_file_contains "auth\s+required\s+pam_faillock.so preauth audit silent deny=5 unlock_time=900" /etc/pam.d/system-auth
_test_file_contains "auth\s+\[success=1 default=bad\]\s+pam_unix.so" /etc/pam.d/password-auth
_test_file_contains "auth\s+\[success=1 default=bad\]\s+pam_unix.so" /etc/pam.d/system-auth
TITLE "5.3.3 Ensure password reuse is limited"
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/password-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+" /etc/pam.d/system-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+.*remember\s*=\s*[5-9]" /etc/pam.d/password-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+.*remember\s*=\s*[5-9]" /etc/pam.d/system-auth
TITLE "5.3.4 Ensure password hashing algorithm is SHA-512"
_test_file_contains "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/password-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so" /etc/pam.d/system-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+.*sha512" /etc/pam.d/password-auth
_test_file_contains "^password\s+sufficient\s+pam_unix.so\s+.*sha512" /etc/pam.d/system-auth
TITLE "5.4.1.1 Ensure password expiration is 365 days or less"
_test_file_contains "^PASS_MAX_DAYS" /etc/login.defs
_test_file_contains "^PASS_MAX_DAYS\s+90" /etc/login.defs
TITLE "5.4.1.2 Ensure minimum days between password changes is 7 or more"
set -x
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I {} chage --list {} | grep "Minimum number of days between password change"
set +x
_test_file_contains "^PASS_MIN_DAYS" /etc/login.defs
_test_file_contains "^PASS_MIN_DAYS\s+[7-9]" /etc/login.defs
TITLE "5.4.1.3 Ensure password expiration warning days is 7 or more"
set -x
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I {} chage --list {} | grep "Number of days of warning before password expires"
set +x
_test_file_contains "^PASS_WARN_AGE" /etc/login.defs
_test_file_contains "^PASS_WARN_AGE\s+[7-9]" /etc/login.defs
TITLE "5.4.1.4 Ensure inactive password lock is 30 days or less"
set -x
egrep ^[^:]+:[^\!*] /etc/shadow | cut -d: -f1 | xargs -I {} chage --list {} | grep "Password inactive"
useradd -D | grep INACTIVE
set +x
if useradd -D | grep -q "INACTIVE=30"; then
        PASSED
else
        FAILED
fi
TITLE "5.4.1.5 Ensure all users last password change date is in the past"
set -x
cat /etc/shadow | cut -d: -f1 | xargs -I {} chage --list {} | grep "Last password change"
set +x
PASSED
TITLE "5.4.2 Ensure system accounts are non-login"
set -x
egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}'
set +x
c=$(egrep -v "^\+" /etc/passwd | awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/sbin/nologin" && $7!="/bin/false") {print}' | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "5.4.3 Ensure default group for the root account is GID 0"
set -x
grep "^root:" /etc/passwd | cut -f4 -d:
set +x
if grep "^root:" /etc/passwd | cut -f4 -d: | grep -q 0; then
        PASSED
else
        FAILED
fi
TITLE "5.4.4 Ensure default user umask is 027 or more restrictive"
_test_file_contains "umask" /etc/bashrc
_test_file_contains "umask 027" /etc/bashrc
_test_file_contains "umask" /etc/profile
_test_file_contains "umask 027" /etc/profile
#_test_file_contains "umask" /etc/profile.d/\*.sh
#_test_file_contains "umask 027" /etc/profile.d/\*.sh
TITLE "5.4.5 Ensure default user shell timeout is 900 seconds or less"
_test_file_contains "TMOUT" /etc/bashrc
_test_file_contains "TMOUT=600" /etc/bashrc
_test_file_contains "TMOUT" /etc/profile
_test_file_contains "TMOUT=600" /etc/profile
TITLE "5.5 Ensure access to the su command is restricted"
_test_file_contains "pam_wheel.so\s+.*use_uid" /etc/pam.d/su
_test_file_contains "wheel:x:10:.*root" /etc/group
TITLE "6.1.1 Audit system file permissions"
PASSED "reviewed"
TITLE "6.1.2 Ensure permissions on /etc/passwd are configured"
_test_file_permission /etc/passwd 0644
TITLE "6.1.3 Ensure permissions on /etc/shadow are configured"
_test_file_permission /etc/shadow 0000
TITLE "6.1.4 Ensure permissions on /etc/group are configured"
_test_file_permission /etc/group 0644
TITLE "6.1.5 Ensure permissions on /etc/gshadow are configured"
_test_file_permission /etc/gshadow 0000
TITLE "6.1.6 Ensure permissions on /etc/passwd- are configured"
_test_file_permission /etc/passwd- 0644
TITLE "6.1.7 Ensure permissions on /etc/shadow- are configured"
_test_file_permission /etc/shadow- 0000
TITLE "6.1.8 Ensure permissions on /etc/group- are configured"
_test_file_permission /etc/group- 0644
TITLE "6.1.9 Ensure permissions on /etc/gshadow- are configured"
_test_file_permission /etc/gshadow- 0000
TITLE "6.1.10 Ensure no world writable files exist"
set -x
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002
set +x
c=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.1.11 Ensure no unowned files or directories exist"
set -x
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
set +x
c=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser|wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.1.12 Ensure no ungrouped files or directories exist"
set -x
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup
set +x
c=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup|wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.1.13 Audit SUID executables"
set -x
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000
set +x
c=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000|wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.1.14 Audit SGID executables"
set -x
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000
set +x
c=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000|wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.1 Ensure password fields are not empty"
set -x
cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}'
set +x
c=$(cat /etc/shadow | awk -F: '($2 == "" ) { print $1 " does not have a password "}' | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.2 Ensure no legacy + entries exist in /etc/passwd"
_test_file_not_contains '^\+:' /etc/passwd
TITLE "6.2.3 Ensure no legacy + entries exist in /etc/shadow"
_test_file_not_contains '^\+:' /etc/shadow
TITLE "6.2.4 Ensure no legacy + entries exist in /etc/group"
_test_file_not_contains '^\+:' /etc/group
TITLE "6.2.5 Ensure root is the only UID 0 account"
set -x
cat /etc/passwd | awk -F: '($3 == 0) { print $1 }'
set +x
c=$(cat /etc/passwd | awk -F: '($3 == 0) { print $1 }' | grep -wc "root")
if [ $c -ne 1 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.6 Ensure root PATH Integrity"
c=$(_test_root_PATH | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.7 Ensure all users' home directories exist"
c=$(_test_user_HOME_dir_exist | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.8 Ensure users' home directories permissions are 750 or more restrictive"
c=$(_test_user_HOME_dir_permission | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi

TITLE "6.2.9 Ensure users own their home directories"
c=$(_test_user_HOME_dir_owner | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.10 Ensure users' dot files are not group or world writable"
c=$(_test_user_HOME_dot_file_writable | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.11 Ensure no users have .forward files"
c=$(_test_user_HOME_forward_dir | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.12 Ensure no users have .netrc files"
c=$(_test_user_HOME_netrc | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.13 Ensure users' .netrc Files are not group or world accessible"
c=$(_test_user_HOME_netrc_perm | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.14 Ensure no users have .rhosts files"
c=$(_test_user_HOME_rhosts | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.15 Ensure all groups in /etc/passwd exist in /etc/group"
c=$(_test_group_integrity | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.16 Ensure no duplicate UIDs exist"
c=$(_test_dup_uid | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.17 Ensure no duplicate GIDs exist"
c=$(_test_dup_gid | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.18 Ensure no duplicate user names exist"
c=$(_test_dup_username | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
TITLE "6.2.19 Ensure no duplicate group names exist"
c=$(_test_dup_groupname | wc -l)
if [ $c -ne 0 ]; then
        FAILED
else
        PASSED
fi
#
