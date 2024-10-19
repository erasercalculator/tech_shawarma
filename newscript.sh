#!/bin/bash
UIDMIN=$(cat /etc/login.defs | grep ^UID_MIN | awk '{print $2}')
UIDMAX=$(cat /etc/login.defs | grep ^UID_MAX | awk '{print $2}')
function check_users(){
    echo "Here are the authorized users"
    python3 allowed_sudoers.py
    echo "\n Here are the other allowed users"
    python3 allowed_users.py

    python3 allowed_sudoers.py > allowed_sudoers.txt
    python3 allowed_users.py > allowed_users.txt

    echo "Merging the allowed sudoers.txt with allowed users.txt"

    cat allowed_sudoers.txt >> allowed_users.txt



    grep sudo /etc/group | awk -F":" '{print $NF}' > actual_sudoers.txt

    cat /etc/passwd | awk -F":" '{print $1, $3}' > temp_users.txt

    python3 actual_users.py > actual_users.txt

    meld allowed_sudoers.txt actual_sudoers.txt
    meld allowed_users.txt actual_users.txt


    
}
function menu() {
    echo "1. Check all users on the system"
    read -r input
    case $input in
    1)check_users;;
    esac
}

menu
