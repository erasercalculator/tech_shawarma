user_file = open("temp_users.txt")

raw_data = user_file.readlines()

user_uid_list = []
for i in raw_data:
	i = i.split()
	if (int(i[1]) >= 1000 and int(i[1]) <= 60000):
		user_uid_list.append(i)

for i in user_uid_list:
	print(i[0])
