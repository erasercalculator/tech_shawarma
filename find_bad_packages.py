#!/usr/bin/python
for i  in open("/home/script_dir/bad_list.txt", "r").readlines():
    match = False
    for j in open("default_packages_ubuntu_22_name_list.txt", "r").readlines():
        if i == j:
            match = True
    if match == False:
        print(i)
