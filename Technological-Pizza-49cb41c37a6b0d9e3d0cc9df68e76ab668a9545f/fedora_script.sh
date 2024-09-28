#!/bin/bash
#Put these variables up top so they are global
SCRIPT_DIR="/home/script_dir"
file_ext=( "mp3" "mp4" "mov" "gif" "mpeg" "jpg" "bmp" "wav" "avi" "aif" "cda" "mid" "midi" "mpa" "ogg" "wma" "wpl" "exe" "msi" "ico" "jpeg" "svg" "tif" "tiff")
#Not removing this as you worked hard to make this list
hackingtools=( packit popem themole wireshark nmap nmapsi4 zenmap john sqlmap medusa crack fakeroot nikto apache netcat logkeys ncrack ophcrack wifite aircrack-ng cracmapexec exploitdb hotpatch laudanum masscan tcpick unicorn-magic )

if [ ! -f "$SCRIPT_DIR/setup_done" ];then
    mkdir "$SCRIPT_DIR"
    touch "$SCRIPT_DIR/setup_done"
fi

function YN_prompt()
{
    while true
    do
        read -p "$1 [Y/n]" ans
        case $ans in 
            [Yy])return 0;;
            [Nn]) return 1;;
            *)
                echo "ERR:Invalid Input! Please enter in Y or N.";;
        esac
    done
}

function separator()
{
    echo ""
    echo "##############################################"
    echo ""
}

function user_continue()
{
    echo "Press any key to continue"
    read -r
}

function backup_file()
{
    if [ -f $2.bak ]; then
        echo "$2.bak already exists in $SCRIPT_DIR."
        if YN_prompt "Replace $2.bak?"; then
            echo "Backing up $1 to $SCRIPT_DIR..."
            cp $1 "$SCRIPT_DIR"
            mv "$SCRIPT_DIR/$2" "$SCRIPT_DIR/$2.bak"
        else
            read -p "Not backing up $1. $2.bak already exists. Press any key to continue..."
            return
        fi
    else
        echo "Backing up $1 to $SCRIPT_DIR..."
        cp $1 "$SCRIPT_DIR"
        mv "$SCRIPT_DIR/$2" "$SCRIPT_DIR/$2.bak"
    fi
}

#diff <file_to_change> <file_as_reference>
#$1 is file to be replaced and $2 is the hardened file
function compare_and_replace()
{
    if diff -q $1 $2; then
        read -p "No differences found. Press any key to continue..."
        return;
    else
        if YN_prompt "$1 is not configured properly. Replace?"; then
            cp $1 "$1.bak"
            mv "$1.bak" .
            cp $2 $1
            echo "$1 replaced. Please check for backups in $PWD."
            if YN_prompt "Verify file by opening gedit?"; then
                gedit $1
            fi 
            return
        else
            read -p "Abort. Press any key to continue..."
            return
        fi
    fi
}

########################### Hardening Functions ###########################

function configure_firewall()
{
    if YN_prompt "Install and enable firewall?"; then
        dnf install firewalld && systemctl --now enable firewalld
        read -p "NOTE: Ports may need to be manually let through. Press any key to return to the main menu..."
        return
    else
        read -p "Press any key to return to the main menu..."
        return
    fi
}

function check_users()
{
    echo "Enter in the users from the cybepatiot README. Enter CTRL+D to stop."
    cat > "authorized_users.txt"
    separator

    #Get users from /etc/passwd
    echo "Getting users with a UID over `grep ^UID_MIN /etc/login.defs | cut -f2 -d " "`"
    awk -F":" -v var=`grep ^UID_MIN /etc/login.defs | cut -f2 -d " "` '{ if ($3>=var) print $1}' /etc/passwd > "users_on_system.txt"
    #Check users by running python script and store output in file.
    python3 check_users.py | tee "bad_users.txt"
    read -p "Check these users."
}

function check_sudoers()
{
    echo "Enter in the sudoers from the cybepatiot README. Enter CTRL+D to stop."
    cat > "authorized_sudoers.txt"

    #Much better
    grep wheel /etc/group | awk -F":" '{print $NF}' | awk -F"," '{i=1}{while ( i <= NF){ print $i; i ++}}' > "sudoers_on_system.txt"
    #Check users by running python script and store output in file.
    separator
    python3 check_sudoers.py | tee "bad_sudoers.txt"
    read -p "Check these unauthorized sudoers."
}

function check_groups()
{
    echo "Here are all the groups with GID over `grep ^GID_MIN /etc/login.defs | cut -f2 -d " "`"
    awk -F":" -v var=`grep ^GID_MIN /etc/login.defs | cut -f2 -d " "` '{ if ($3>=var) print $1}' /etc/group #Use command substitution to get min GID then use awk to search /etc/group
    separator
    user_cont
}

function change_passwords()
{
    if [ -f $SCRIPT_DIR/done_PAM ]; then
        read "PAM hardening has been complete. You may proceed with changing passwords. Press any key to continue..."
    else
        echo "PAM hardening has not been completed. Please do that first."
        echo "Or, done_PAM file could not be found in $SCRIPT_DIR"
        read -p "Please press any key to return to the main menu..."
        return
    fi

    #Creates a file with all users UID in the format chpasswd likes.
    awk -F":" '{ if ($3>=1000) print $1":0ld$cona1"}' /etc/passwd > "$SCRIPT_DIR/new_passwds.txt"
    read -p "Opening file for changing passwords. Make sure to remove the default account otherwise you will need the restart the image. Press any key to continue..."
    gedit "$SCRIPT_DIR/new_passwds.txt"
    chpasswd < "$SCRIPT_DIR/new_passwds.txt" && read -p "Passwords successfully changed. Press any key to continue..."
}

function check_services()
{
    services=( "avahi-daemon.service" "avahi-daemon.socket" "cups" "isc-dhcp-server" "slapd" "nfs-kernel-server" "bind9" "vsftpd" "ftp" "pureftpd" "apache2" "dovecot-imapd" "dovecot-pop3d" "samba" "squid" "snmp" "nis" "rsync" "rsh-client" "talk" "telnet" "rpcbind" "postfix" )
    read -p "Disabling services. Press any key to continue..."
    for i in "${services[@]}"
    do
        separator
        systemctl status "$i"
        separator
        if YN_prompt "Disable and stop $i?"; then
            systemctl stop "$i"
            systemctl disable "$i"
        fi 
        separator
        systemctl status "$i"
        user_continue
    done
    read -p "Done checking services. Press any key to continue..."
}

function hacking_tools()
{
    hacktools=$(cat hacking_tools_names_kali_2021.txt)
    for i in "${hacktools[@]}"; do 
        apt remove "$i"
    done
    user_continue
}

function locate_media()
{
    echo "Bad files will be found using the locate command. Output will later be put into a file for further exmination."    
    user_continue
    for i in "${file_ext[@]}"; do
        locate *.$i | tee "$SCRIPT_DIR/$i-files.txt"
        echo "Take note for any suspicous files and delete them later after invetigating!"
        user_continue
    done
    echo "Done searching for bad files."
    user_continue
}

function sys_file_perms()
{
    sys_files=(
    "/etc/passwd"
    "/etc/passwd-"
    "/etc/group"
    "/etc/group-"
    "/etc/shadow"
    "/etc/shadow-"
    "/etc/gshadow"
    "/etc/gshadow-"

    separator
    ls -l ${sys_files[@]}
    separator
    
    if YN_prompt "Set up proper owner and file permissions for the above files?"; then
        if YN_prompt "Change owner for all file to root?"; then
            chown root:root ${sys_files[@]} && echo "All files\' owner and group changed to root!"
        fi
        if YN_prompt "Set all the shadow files permissions to 0000?"; then
            chmod 0000 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- && echo "Shadow files\' permissions set to 0000!"
        fi
        if YN_prompt "Set /etc/passwd and /etc/group along with their backups to 640?"; then
            chmod 640 /etc/passwd /etc/passwd- /etc/group /etc/group- && echo "Files\' permissions set to 640!"
        fi
        if YN_prompt "Verify files?"; then
            separator
            ls -l ${sys_files[@]}
            separator
        fi
        read -p "Done setting up file permissions. Press any key to continue..."
        return
    else
        read -p "Skipping this section. Press any key to continue..."
        return
    fi
}

function disable_guest()
{
    echo "Add AllowGuest=false"
    read response
    gedit /etc/gdm3/custom.conf
}

function harden_PAM()
{
    backup_file /etc/login.defs login.defs

    sed -i -e 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' -e 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t10/' -e 's/^PASS_WARN_AGE.*/PASS_WARN_AGE\t7/' /etc/login.defs

    echo "Verify the following in /etc/login.defs:"
    echo "PASS_MIN_DAYS 10"
    echo "PASS_MAX_DAYS 90"
    echo "PASS_WARN_AGE 7"
    read -p "Press any key to open /etc/login.defs..."
    gedit /etc/login.defs

    separator

    backup_file /etc/security/pwquality.conf pwquality.conf 

    echo "Verify the following /etc/security/pwquality.conf
    minlen = 8
    minclass = 4
    lcredit = -1
    ucredit = -1
    dcredit = -1    
    ocredit = -1
    difok = 5
    maxrepeat = 2 (consecutive characters?)"

    declare -A pw_checks=(

    [minlen]="minlen = 8"
    [minclass]="minclass = 4"
    [lcredit]="lcredit = -1"
    [ucredit]="ucredit = -1"
    [dcredit]="dcredit = -1"
    [ocredit]="ocredit = -1"
    [difok]="difok = 5"
    [maxrepeat]="maxrepeat = 2"

    )
    
    for key in "${!pw_checks[@]}"
    do
        sed -i 's/^[#].*$key.*=.*/$pw_checks[$key]/' /etc/security/pwquality.conf
    done    

    read -p "Press any key to open /etc/security/pwquality.conf..."
    gedit /etc/security/pwquality.conf

    separator

    read -p "Configuring pam_faillock config file: faillock.conf. Press any key to continue..."
    backup_file /etc/security/faillock.conf faillock.conf   
    sed -i -e 's/^[#].*audit.*/audit/' -e 's|^[#].*dir.*=.*|dir = /var/run/faillock|' -e 's/^[#].*deny.*=.*/deny = 3/' -e 's/^[#].*fail_interval.*=.*/fail_interval = 900/' -e 's/^[#] unlock_time.*=.*/unlock_time = 1800/' /etc/security/faillock.conf   
    read -p "Verify that faillock.conf is properly configured. Press any key to continue..."
    gedit /etc/security/faillock.conf 

    separator

    read -p "Configuring PAM files now. Press any key to continue"...
    backup_file /etc/pam.d/common-account common-account
    backup_file /etc/pam.d/common-auth common-auth
    backup_file /etc/pam.d/common-password common-password

    read -p "
    Verify that:
    account required                        pam_faillock.so
    has been added to /etc/pam.d/common-account. Press any key to continue..."
    
    echo "account required                        pam_faillock.so" >> /etc/pam.d/common-account
    gedit /etc/pam.d/common-account
    
    read -p "Add remember=5 to /etc/pam.d/ after the line with pan_unix.so in it"
    gedit /etc/pam.d/common-password
    
    cat common-auth-exemplar
    read -p "This one is the hardest. Follow the example file below for configuring common-auth. Make sure to have a root shell open in case you are locked out!"
    gedit /etc/pam.d/common-auth 

    separator

    read -p "Changing permissions to files in /etc/pam.d. First confirm if there are any anomoulies. Press any key to continue..."
    ls -l /etc/pam.d/

    if YN_prompt "Change permissions?";then
        chown root:root /etc/pam.d/*
        chmod u+rw g+r o+r /etc/pam.d/*
    fi
    
    touch "$SCRIPT_DIR/done_PAM"
    read -p "Done configuring PAM. Press any key to continue..."
}

function bootup_check()
{
    echo "Launch Start Up applications using GUI."
    user_continue
}

function uid_check()
{
    awk -F: '($3 == "0") {print}' /etc/passwd
    echo "
    If you see someone other than root, there may be a problem. Ensure all these accounts are authorized to run as UID 0."
    user_continue
}

#Great use of awk again!
function empty_passcheck()
{
    awk -F: '($2 == "") {print}' /etc/shadow
    echo "There shouldnt be users with empty passwords (normally)..."
    user_continue
}

function cron_hardening()
{
    if !(rpm -q cronie); then
        read -p "Cron does not seem to be installed. Press any key to return..."
        return
    fi    

    echo "Enabling cron. Then opening crontab to check for any suspicous tasks. Finally, setting proper permissions on cron files."
    user_continue
    
    separator
    echo "Enabling cron..."
    systemctl --now enable cron
    separator
    
    if YN_prompt "Opening crontab. Check if there are any suspicous files. Please reference with a clean crontab exemplar."
        then gedit /etc/crontab
    fi
    separator
    cron_files=("/etc/crontab" "/etc/cron.hourly/" "/etc/cron.daily/" "/etc/cron.weekly/" "/etc/cron.monthly/" "/etc/cron.d/")
    echo "Now setting permissions for cron files."
    user_continue
    for i in "${cron_files[@]}"
    do
        if YN_prompt "Changing owner and group to root along with removing group and other privileges on $i."
            then
            chown -R root:root "$i"
            chmod -R og-rwx "$i"
        fi
    done
    if [ ! -f "/etc/cron.allow" -a ! -f "/etc/cron.deny" ];then
        if YN_prompt "Neither cron.allow nor cron.deny exist. Create cron.allow?"; then
            touch /etc/cron.allow
        fi
    elif [ -f "/etc/cron.deny" -a ! -f "/etc/cron.deny" ];then
        if YN_prompt "cron.deny exists but cron.allow does not. Check cron.deny to see if blank?";then
            gedit /etc/cron.deny
        fi
        if YN_prompt "Delete cron.deny?"; then
            rm /etc/cron.deny
        fi
        if YN_prompt "Create cron.allow?"; then
            touch /etc/cron.allow
        fi
    elif [  -f "/etc/cron.allow" -a  -f "/etc/cron.deny" ];then
        if YN_prompt "cron.deny exists along with cron.allow. Check cron.deny to see if blank?";then
            gedit /etc/cron.deny
        fi
        if YN_prompt "Delete cron.deny?"; then
            rm /etc/cron.deny
        fi
    fi
    separator
    systemctl status cron  | grep Active
    separator && read -p "Cron hardening complete! Press any key to continue"
}

function at_hardening()
{
    if !(rpm -q at); then
        read -p "at is not installed. Press any key to return..."
        return
    fi

    if [ ! -f "/etc/at.allow" -a ! -f "/etc/at.deny" ];then
        if YN_prompt "Neither at.allow nor at.deny exist. Create at.allow?"; then
            touch /etc/at.allow
        fi
    elif [ -f "/etc/at.deny" -a ! -f "/etc/at.deny" ];then
        if YN_prompt "at.deny exists but at.allow does not. Check at.deny to see if blank?";then
            gedit /etc/at.deny
        fi
        if YN_prompt "Delete at.deny?"; then
            rm /etc/at.deny
        fi
        if YN_prompt "Create at.allow?"; then
            touch /etc/at.allow
        fi
    elif [  -f "/etc/at.allow" -a  -f "/etc/at.deny" ];then
        if YN_prompt "at.deny exists along with at.allow. Check at.deny to see if blank?";then
            gedit /etc/at.deny
        fi
        if YN_prompt "Delete at.deny?"; then
            rm /etc/at.deny
        fi
    fi
}

function ssh_config() 
{
    declare -A ssh_configs=(
    
    [PermitEmptyPasswords]="PermitEmptyPasswords no"
    [ClientAliveInterval]="ClientAliveInterval 300"
    [ClientAliveCountMax]="ClientAliveCountMax 2"
    [Protocol]="Protocol 2"
    [Port]="Port 2025"
    [IgnoreRhosts]="IgnoreRhosts yes"
    [HostbasedAuthentication]="HostbasedAuthentication no"
    [X11Forwarding]="X11Forwarding no"
    [PermitUserEnvironment]="PermitUserEnvironment no"
    [AllowAgentForwarding]="AllowAgentForwarding no"
    [AllowTcpForwarding]="AllowTcpForwarding no"
    [PermitTunnel]="PermitTunnel no"
    [MaxAuthTries]="MaxAuthTries 3"
    [LoginGraceTime]="LoginGraceTime 20"
    [UsePrivilegeSeparation]="UsePrivilegeSeparation yes"
    [UsePAM]="UsePAM yes"
    [UseTCPWrappers]="UseTCPWrappers yes"
    [MaxSessions]="MaxSessions 2"
    [LogLevel]="LogLevel VERBOSE"
    [Compression]="Compression NO"
    
    )
    
    backup_file /etc/ssh/sshd_config sshd_config
    
    echo "Hardening sshd_config..."
    for key in "${!ssh_configs[@]}"
    do
        sed -i 's/^[#]$key/$ssh_configs[$key]/' /etc/ssh/sshd_config
    done
    
    for key in "${!ssh_configs[@]}"
    do
        if !(grep -q "${ssh_configs[$key]}" /etc/ssh/sshd_config)
            then echo "${ssh_configs[$key]}">> /etc/ssh/sshd_config
        fi
    done

    if YN_prompt "Change permissions on sshd_config? Changing owner and group to root along with removing group and other rwx permissions?"; then
        chown root:root /etc/ssh/sshd_config
        chmod og-rwx /etc/ssh/sshd_config
    fi
  
    if YN_prompt "Verify /etc/sshd?"; then
        gedit /etc/ssh/sshd_config
    fi

    echo "Done hardening ssh!"
    user_continue
 #PubkeyAuthentication yes (IF NOT USING PASSWORDS)



#     IF NOT USING, DISABLE THESE:
#     ChallengeResponseAuthentication no
#     KerberosAuthentication no
#     GSSAPIAuthentication no
#     PasswordAuthentication no (IF USING KEY BASED AUTHENTICATION)
}

function nginx_config()
{
    echo "You are about to configure the Nginx server for the following settings.
    Add or change the following:

server_tokens off;

        Size Limits & Buffer Overflows 
  client_body_buffer_size  1K;
  client_header_buffer_size 1k;
  client_max_body_size 1k;
  large_client_header_buffers 2 1k;

  add_header X-XSS-Protection 1; mode=block;"
    
    read response
    gedit /etc/nginx/nginx.conf


    user_continue
}

function etcsys_config()
{
    echo "You are about to configure the /etc/sysctl.config file for the following settings."
    
    sysctl_configs=(
    
    "net.ipv4.icmp_echo_ignore_broadcasts=1"
    "net.ipv4.icmp_ignore_bogus_error_responses=1"
    "net.ipv4.tcp_syncookies=1"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.ip_forward=0"
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.default.send_redirects=0"
    "kernel.randomize_va_space=2"
    "fs.protected_symlinks=1"
    "fs.protected_hardlinks=1"
    "kernel.kptr_restrict=2"
    "kernel.sysrq=0"
    "kernel.randomize_va_space=2"
    "fs.protected_fifos=2"
    "fs.protected_regular=2"
    "fs.suid_dumpable=0"
    "kernel.core_uses_pid=1"
    "kernel.ctrl-alt-del=0"
    "kernel.dmesg_restrict=1"
    "kernel.perf_event_paranoid=3"
    "kernel.unprivileged_bpf_disabled=1"
    "net.core.bpf_jit_harden=2"
    "net.ipv4.conf.all.bootp_relay=0"
    "net.ipv4.conf.all.forwarding=0"
    "net.ipv4.conf.all.mc_forwarding=0"
    "net.ipv4.conf.all.proxy_arp=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.tcp_timestamps=0"
    
    )

    backup_file /etc/sysctl.conf sysctl.conf
    
    echo "Hardening sysctl.conf..."
    for conf in "${sysctl_configs[@]}"
    do
        if !(grep -q "$conf" /etc/sysctl.conf)
            then echo "$conf" >> /etc/sysctl.conf
        fi
    done
    
    separator
    echo "REPITIONS:"
    for i in "${sysctl_configs[@]}"
    do
        check=`echo $i | sed 's/=.//'`
        if [ `grep -c ^$check /etc/sysctl.conf` -gt 1 ]
            then echo "$check is repeated!"
        fi
    done
  
    if YN_prompt "Verify /etc/sysctl.conf?"; then
        gedit /etc/sysctl.conf
    fi

    echo "Done hardening /etc/sysctl.conf!"
    user_continue
}

function rkhunter()
{
    echo "Install rkhunter with sudo apt install rkhunter and use rkhunter --check to get a general, quick check ~around 2 mins~ for rootkits and some extra file config settings.

    If you want to check the log, gedit /etc/rkhunter.conf"

    user_continue
}

# function hashing_rounds()
# {
#     echo "Step 1. To configure minimum and maximum hashing rounds, add, change, or uncomment the following in /etc/login.defs
#     SHA_CRYPT_MIN_ROUNDS 5000
#     SHA_CRYPT_MAX_ROUNDS 5000
#     "
#     read response

#     sudo gedit /etc/login.defs

#     echo "Step 2. Ensure the settings is also configured for /etc/pam.d/common-auth.
#     Add it as a parameter to pam_unix.so
#     'rounds=5000'.
#     "
    
#     read response 

#     sudo gedit /etc/pam.d/common-auth

#     user_continue

# }

function sudo_hardening()
{
    if YN_prompt "You are about to configure the /etc/sudoers.d file for the following settings."; then
        chown -R root:root /etc/sudoers.d
        chmod og-rwx /etc/sudoers.d
    fi

    backup_file "/etc/sudoers" "sudoers"

    sudo_conf=(
    "Defaults.*use_pty"
    "Defaults.*logfile=logfile=\"/var/log/sudo.log\""
    "^[^#].*NOPASSWD"
    "^[^#].*\!authenticate"
    "timestamp_timeout=.*[0-9]*"
    "Defaults.*!visiblepw"
    )

    for conf in "${sudo_confs[@]}"
    do
        if !(grep -qr "$conf" /etc/sudoers)
            then echo "Please add the following to /etc/sudoers: $conf"
        fi
    done

    echo "Make sure that wheel group only has sudo priveleges along with root!"
    echo "Open another terminal and run \"visudo\" to edit the sudoers file!"
    read -p "Press any key to continue..."
    
}

function umaskconfig()
{
    echo "You are about to configure the /etc/login.defs for the following settings
    UMASK 027
    "
    read response
    gedit /etc/login.defs

    echo "Also add it to these few files here, (ex./etc/profile)
    THIS TIME LOWERCASE 
    umask 027"
    read response
    gedit /etc/profile

    echo "Finally, /etc/bash.bashrc
    add
    umask 027
    "
    read response
    gedit /etc/bash.bashrc

    user_continue
}

function auditdconfig()
{
    echo "Install auditd with 'sudo apt install auditd'
    
    Then, add or change the following lines:
    
    
    "
    read response
    gedit /etc/audit/auditd.conf

    user_continue
}

function keybased_auth()
{
    echo "You are about to enable key based authentication. (y/n)
        "
        if [ "$response" == y ] || [ "$response" == Y ]; then
        ssh-keygen
        read response
        echo "Use this command (ssh-copy-id username@remote_host). If you somehow forgot your host ip, use ifconfig."
        echo "Lastly, REMEMBER TO SET PasswordAuthentication no and SET PubkeyAuthentication yes (IF NOT USING PASSWORDS)"
        else
        user_continue
        fi
        user_continue
}

function bruteforce_file()
{
    if YN_prompt "This will install the 'rockyou.txt', commonly used to brute force passwords."; then
        wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    fi
    user_continue   
}

function permit_deny()
{
echo "These are the hashes of both files. If they are the same, that means something is bad."
echo "pam_permit.so     :"
sha256sum /lib/x86_64-linux-gnu/security/pam_permit.so

echo "pam_deny.so       :"
sha256sum /lib/x86_64-linux-gnu/security/pam_deny.so
user_continue
}

function gid_uid()
{
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
 [ -z "$x" ] && break
 set - $x
 if [ $1 -gt 1 ]; then
 users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
 echo "Duplicate UID ($2): $users"
 fi
done
user-continue
}

function shadow_check()
{
 awk -F: '($1=="shadow") {print $NF}' /etc/group
 awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
echo "This user was found to be in the shadow group. If it is empty, it is fine. If not, investigate!"
user_continue
}

function check_for_duplicates()
{


cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
echo "Duplicate group name $x in /etc/group"
done


cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
 echo "Duplicate login name $x in /etc/passwd"
done

user-continue
}

function unowned_check()
{

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
user_continue
}

function find_bad_packages()
{
    dnf list --installed | awk '{print $1}' | sed '1d' > $SCRIPT_DIR/bad_list.txt
    python3 find_bad_packages.py | tee $SCRIPT_DIR/check_these_packages.txt
    separator
    read -p "Please check these packages manually as there could be false positives! Press any key to continue..."
}

function reminders()
{
    echo "Friendly reminders, especially when stuck or lost!
    
    -Nginx off slash vuln
    -Use common sense. If a forensics question was asking about a service, do not automatically assume that service is needed. Remember RCON from the narnia image?
    -Ensure that you checked /etc/passwd for 'hidden users' below uid 1000. 
    -For backdoors, remember to 'netstat -antp' and 'ps-aux'. For netstat, be on the lookout for any connections that are listening on unusual ports or connected to unfamilar IP addresses.
    for ps -aux be on the lookout for any processes with weird command line arguments and stuff that runs as root.
    -LYNIS
    -Ensure no random users are added to groups they shouldnt be in. For instance, some random user should not be in the shadow group.
    -IF NOT USING MOTD, CONSIDER CHANGING PERMISSIONS ON IT OR DELETING THE FILE  chown root:root /etc/motd    |    chmod u-x,go-wx /etc/motd
    "
}


function menu()
{
    echo "ALL YES/NO questions should be answered with single letters, (ex. y, n)."
    echo "1. UFW update/installation."
    echo "40. Harden PAM"
    echo "reminders. Reminders"
    
    read -r user_input
    case $user_input in
        1)configure_firewall;;
        2)check_users;;
        3)check_sudoers;;
        4)check_groups;;
        5)change_passwords;;
        6)check_services;;
        7)locate_media;;
        8)cron_hardening;;
        9)at_hardening;;
        10)sys_file_perms;;
        

        40)harden_PAM;;
     

     
        reminders)reminders;;
        
            *) echo "ERR Invalid Input"
                user_continue;;
    esac
}

while true; do
menu
done
