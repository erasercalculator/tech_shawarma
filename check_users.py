#!/usr/bin/python

for i  in open("users_on_system.txt", "r").readlines():
    match = False
    for j in open("authorized_users.txt", "r").readlines():
        if i == j:
            match = True
    if match == False:
        print(i)
