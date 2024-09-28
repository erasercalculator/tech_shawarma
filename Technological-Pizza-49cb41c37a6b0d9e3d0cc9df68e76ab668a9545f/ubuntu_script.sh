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
    grep sudo /etc/group | awk -F":" '{print $NF}' | awk -F"," '{i=1}{while ( i <= NF){ print $i; i ++}}' > "sudoers_on_system.txt"
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
    user_continue
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

function ufw()
{
    apt-get update
    apt install ufw
    systemctl start ufw
    systemctl enable ufw
    echo "This is the status of UFW"
    systemctl status ufw
    user_continue
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

function update_os()
{
  
    
    if YN_prompt "Are you sure you want to proceed? Doing this may take an extensive amount of time (y/n?)"; then
    apt-get update
    apt-get upgrade -y
    fi
    user_continue

}

function remove_games()
#will add more here, possible cutting out everything except the app name and removing it.
{
    dpkg -l | grep game
    user_continue
}


function user_add()
{
    echo "Enter in the names of the users you would like to add."
    read -ra users
    for i in "${users[@]}";do
    adduser "$i"
    done
    user_continue
}

function group_add()
{
    echo "Type out the name of the group you would like to add"
    read -r group
    addgroup "$group"
    echo "List the members you would like to add to this group"
    read -ra members
    for i in "${members[@]}";do
    adduser "$i" "$group"
    done
    user_continue
}
function locate_media()
#apparently for some reason this code prints out svg files?
#Modified this so it saves output and displays it in a more orderly fashion
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
    )
    separator
    ls -l "${sys_files[@]}"
    separator
        
    if YN_prompt "Set up proper owner and file permissions for the above files?"; then
        if YN_prompt "Change owner for all file to root?"; then
            chown root:root "${sys_files[@]}" && echo "All files\' owner and group changed to root!"
        fi  
        if YN_prompt "Set all the shadow files permissions to 0000?"; then
            chmod 0000 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow- && echo "Shadow files\' permissions set to 0000!"
        fi  
        if YN_prompt "Set /etc/passwd and /etc/group along with their backups to 640?"; then
            chmod 640 /etc/passwd /etc/passwd- /etc/group /etc/group- && echo "Files\' permissions set to 640!"
        fi  
        if YN_prompt "Verify files?"; then
            separator                                                                                                                                                                                                                         
            ls -l "${sys_files[@]}"
            separator
        fi  
        read -p "Done setting up file permissions. Press any key to continue..."
        return
    else
        read -p "Skipping this section. Press any key to continue..."
        return
    fi  
}

function etcgroup_configure()
{
   if YN_prompt "This is going to run the following commands. Are you sure? 
   chmod u-x,go-wx /etc/group
   chown root:root /etc/group"; then
    chown root:root /etc/group
    chmod u-x,go-wx /etc/group
    else
    user_continue
    fi

}

# function etcshadow_configure()
# {
#      echo "This is going to run the following commands. Are you sure? 
#    chmod u-x,g-wx,o-rwx /etc/shadow
#    chown root:root /etc/shadow"
#    read response
#    if [ "$response" == y ] || [ "$response" == Y ]; then
#     chown root:root /etc/shadow
#     chmod u-x,g-wx,o-rwx /etc/shadow
#     else
#     user_continue
#     fi
# }

# function etcgshadow_configure()
# {
#       echo "This is going to run the following commands. Are you sure? 
#    chmod u-x,g-wx,o-rwx /etc/gshadow
#    chown root:root /etc/gshadow"
#    read response
#    if [ "$response" == y ] || [ "$response" == Y ]; then
#     chown root:root /etc/gshadow
#     chmod u-x,g-wx,o-rwx /etc/gshadow
#     else
#     user_continue
#     fi
# }
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

function config_sudo()
{
    
    config_sudo_menu
    
    read -r user_input

    case $user_input in
    1)defaults_pty;;
    2)sudo_log_exist;;
    3)timeout_value;;
    4)sudo_log_dir;;
    5)etcsudoers.d;;

    *) echo "ERR Invalid Input"
    config_sudo;;

    esac

  




user_continue
}
function defaults_pty()
  {
    echo "Be prepared to enter this command into the text file. It's using visudo, so copy this command if you want to paste it.

    Defaults use_pty
"



if YN_prompt "Do you want to open this file?" ; then
    visudo -f /etc/sudoers
fi
user_continue
}

function sudo_log_exist()
{
echo "Checking for log files....."
awk '/Defaults\s+logfile="\/var\/log\/sudo.log"/' /etc/sudoers

echo "If there is no result, that meants you must add the following lines by visudo.
Defaults        logfile=\"/var/log/sudo.log\"    
Ensure you keep the quotations and the tab! Either visudo, or access /etc/sudoers!"
}

function timeout_value()
{
echo "Checking timeout..."
grep -roP "timestamp_timeout=\K[0-9]*" /etc/sudoers*
echo "If this is empty, ensure that timeout is 5 minutes. If it is not empty, configure timeout. Use visudo or /etc/sudoers

Like this if 'env reset' has its own seperate line:
Defaults timestamp_timeout=15

Like this if it doesnt:
Defaults env_reset, timestamp_timeout=15

Do only one!
"
}
function bootup_check()
{
    echo "Launch Start Up applications using GUI."
    user_continue
}
#Great use of awk
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
    echo "
    There shouldnt be users with empty passwords (normally)...."
    user_continue
}

function cron_hardening()
{
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
    separator
    systemctl status cron  | grep Active
    separator && read -p "Cron hardening complete! Press any key to continue"
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
        if ! (grep -q "${ssh_configs[$key]}" /etc/ssh/sshd_config)
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
        if ! (grep -q "$conf" /etc/sysctl.conf)
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

function etcsudoers.d()
{
    if YN_prompt "You are about to configure the /etc/sudoers.d file for the following settings."; then
        chown root:root /etc/sudoers.d
        chmod og-rwx /etc/sudoers.d
    fi
    user_continue
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
 
        if YN_prompt "You are about to enable key based authentication. (y/n)"; then
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
read lol
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
read lol
user_continue
}

function configure_updates()
{
    if YN_prompt "Opening GUI thing that controls updates."; then
        software-properties-gtk
    fi
    user_continue
}

function shadow_check()
{
 awk -F: '($1=="shadow") {print $NF}' /etc/group
 awk -F: -v GID="$(awk -F: '($1=="shadow") {print $3}' /etc/group)" '($4==GID) {print $1}' /etc/passwd
echo "This user was found to be in the shadow group. If it is empty, it is fine. If not, investigate!"
read lol
user_continue
}

function same_name()
{


cut -d: -f1 /etc/group | sort | uniq -d | while read -r x; do
 echo "Duplicate group name $x in /etc/group"
done


cut -d: -f1 /etc/passwd | sort | uniq -d | while read -r x; do
 echo "Duplicate login name $x in /etc/passwd"
done
read lol
user_continue
}

function unowned_check()
{

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser
read lol
user_continue
}

function sudo_log_dir()
{
echo "If you wish to be moved to the directory of the sudo log file, input the command 'cd /var/log'. If you wish, you may inspect the file, or the directory itself for any weird permissions. The file is probably called sudo.log, or something similar."

ls -al | grep sudo
user_continue
}

function find_bad_packages()
{
    dpkg -l | sed '1,5d' | awk '{print $2}' | sed 's/:amd64//'> $SCRIPT_DIR/bad_list.txt
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

function config_sudo_menu()
{
    echo "1. Defaults use pty"
    echo "2. Ensure sudo log file exists."
    echo "3. Checking for timeout value."
    echo "4. Check for privileged command usage."
    echo "5. Permission for directory /etc/sudoers.d"
}

# function passwd_lockout_menu()
# {

# 	echo "1. Change password age requirements."
# 	echo "2. Password requirements. (ex.Length, letters, etc.)"
# 	echo "3. Account lockout policy"

# }

function menu()
{
    echo "ALL YES/NO questions should be answered with single letters, (ex. y, n)."
    echo "1. UFW update/installation."
    echo "2. Check for services."
    echo "3. Check for hacking tools/remove."
    echo "4. Update the OS."
    echo "5. Show potential games."
    echo "6. Create a group and add users"
    echo "7. Add users to the system"
    echo "8. Locate and display media files."
    echo "9. Configure system file permissions (/etc/passwd, /etc/group)".
    # echo "12. Configure /etc/shadow permissions."
    # echo "13. Configure /etc/gshadow permissions."
    echo "10. Disable guest login."
    echo "11. Configure sudo file"
    echo "12. Check what things are launched when you boot up your pc. Start-Up Applications will be used."
    echo "13. Ensure only root has the UID of 0."
    echo "14. Verify no accounts have empty passwords"
    echo "15. Secure and harden cron."
    echo "16. Find unauthorized users."
    echo "17. Change passwords for all users except default account."
    echo "18. Check sudoers."
    echo "19. /etc/ssh/sshd_config hardening"
    echo "20. Nginx configuration"
    echo "21. /etc/sysctl.conf Hardening"
    echo "22. rkhunter (rootkit and some extra file checks)"
    echo "23. umask config"
    echo "24. Ensure auditd is installed and configured."
    echo "25. Enable key based authentication on SSH."
    echo "26. Install the 'rockyou.txt' file commonly used for brute forcing passwords."
    echo "27. Check groups"
    echo "28. Ensure that pam_permit.so has not maliciously replaced pam_deny.so"
    echo "29. Ensure no duplicate UID/GID."
    echo "30. Configure updates through the GUI thing."
    echo "31. Ensure shadow group is empty."
    echo "32. Ensure no groups or users share the same names."
    echo "33. Ensure no unowned files or directories exist"
    echo "34. Harden PAM"
    echo "reminders. Reminders"
    
    read -r user_input
    case $user_input in
        1)ufw;;
        2)check_services;;
        3)hacking_tools;;
        4)update_os;;
        5)remove_games;;
        6)group_add;;
        7)user_add;;
        8)locate_media;;
        9)sys_file_perms;;
        10)disable_guest;;
        #11)passwdage_requirements;;
        #12)passwd_requirements;;
        #13)account_lockout;;
        11)config_sudo;;
        12)bootup_check;;
        13)uid_check;;
        14)empty_passcheck;;
        15)cron_hardening;;
        16)check_users;;
        17)change_passwords;;
        18)check_sudoers;;
        19)ssh_config;;
        20)nginx_config;;
        21)etcsys_config;;
        22)rkhunter;;
        23)umaskconfig;;
        24)auditdconfig;;
        25)keybased_auth;;
        26)bruteforce_file;;
        27)check_groups;;
        28)permit_deny;;
        29)gid_uid;;
        30)configure_updates;;
        31)shadow_check;;
        32)same_name;;
        33)unowned_check;;
        34)harden_PAM;;
    

     
        reminders)reminders;;
        
            *) echo "ERR Invalid Input"
                user_continue;;
    esac
}

while true; do
menu
done
