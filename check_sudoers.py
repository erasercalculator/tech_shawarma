#!/usr/bin/python

for i  in open("sudoers_on_system.txt", "r").readlines():
    match = False
    for j in open("authorized_sudoers.txt", "r").readlines():
        if i == j:
            match = True
    if match == False:
        print(i)
