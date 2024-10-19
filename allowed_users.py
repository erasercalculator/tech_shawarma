users_file = open("users.txt")

raw_data = users_file.readlines()

user_list = []

count_users = False

counter = 0

for i in raw_data:
	if (count_users == True):
		if (counter % 2 == 0):
			pass
		if (counter % 2 != 0):
			user_list.append(i)
	if ("Authorized Users:" in i):
		count_users = True
	counter +=1

loop_counter = 0
for i in user_list:
	user_list[loop_counter] = i.strip()
	loop_counter += 1
	
for i in user_list:
	print(i)
	
users_file.close()
