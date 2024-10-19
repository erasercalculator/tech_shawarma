users_file = open("users.txt")

raw_data = users_file.readlines()

user_list = []

count_users = False

counter = 0

for i in raw_data:
	if (count_users == True):
		if ("Authorized Users" in i):
			count_users = False
		if (counter % 2 == 0):
			pass
		if (counter % 2 != 0):
			user_list.append(i)
	if ("Authorized Administrators:" in i):
		count_users = True
	counter +=1
	
loop_counter = 0
for i in user_list:
	if ("(you)" in i):
		user_list[loop_counter] = i.replace("(you)", "")
	user_list[loop_counter] = user_list[loop_counter].strip()
	loop_counter += 1

for i in user_list:
	if (i == ""):
		user_list.remove(i)
		
for i in user_list:
	print(i)

users_file.close()
