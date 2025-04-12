from exrex import generate
from zipfile import ZipFile 
path = 'secret7/'
for number_archive in range(6, -1, -1):
	with open(path + 'password.txt') as file:
		password_regex = file.read().strip()
	password_list = list(generate(password_regex))
	print(password_regex)
	print('Passwords list len: ' + str(len(password_list)))
	test_open = False
	for i in password_list:
		with ZipFile(path + 'secret' + str(number_archive) + '.zip', "r") as zip:
			try:
				zip.extractall(path="secret" + str(number_archive), pwd=i.encode("utf-8"))
				with open("secret" + str(number_archive) + "/secret" + str(number_archive) + '/correct.txt') as file:
					s = file.read().strip()
					if 'correct' in s:
						test_open = True
						break
			except:
				pass
	path = "secret" + str(number_archive) + "/" + "secret" + str(number_archive) + "/"
	if test_open:
		print('open ' + "secret" + str(number_archive))
	else:
		print('cant open next archive')
		break