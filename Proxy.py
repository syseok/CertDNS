import socket
import os
import sys
import struct
import codecs
import _thread
import dnslib
import binascii
import base64
import subprocess

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

import time

key_cache_dict = dict()

# convert the UDP DNS query to the TCP DNS query
def getTcpQuery(query):
	message = b'\x00'+ bytes(chr(len(query)),'utf-8') + query
	return message

# send a TCP DNS query to the DNS server
def sendTCP(DNSserverIP, query):
	server = (DNSserverIP, 53)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server)
	tcp_query = getTcpQuery(query)
	sock.send(tcp_query)  	
	data = sock.recv(10240)
	return data


def validate(dns_record,DNSserverIP):
	global key_cache_dict

	publickey_path = ""
	cert_loc = ""

	#find cache first
	domain_name = str(dns_record.questions[0].qname)

	# print("============DNS record (TXT)==============")
	txt_q = dnslib.DNSRecord.question(dns_record.questions[0].qname,"TXT")
	# print(txt_q.pack())
	txt_q_time = time.time()
	TCPanswer = sendTCP(DNSserverIP, txt_q.pack())
	# print("TXT query time :",time.time()-txt_q_time)


	if(TCPanswer):
		rcode = codecs.encode(TCPanswer[:6],'hex')
		rcode = str(rcode)[11:-1]

		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			# print ("Success!")

			signaturegentime = time.time()

			UDPanswer = TCPanswer[2:]
			txt_dd = dnslib.DNSRecord.parse(UDPanswer)
			pkiiii = txt_dd.rr[0].rdata.toZone()
			siglist = pkiiii[1:-1].split('" "')
			signature_l=["",""]


			for sigs in siglist:
				if(sigs.startswith("CertDNS_Base64_A_1")):
					signature_l[0]=(sigs.replace("CertDNS_Base64_A_1:",""))

				if(sigs.startswith("CertDNS_Base64_A_2")):
					signature_l[1]=(sigs.replace("CertDNS_Base64_A_2:",""))		

			signature=signature_l[0]+signature_l[1]

			# print("signature generation :",time.time()-signaturegentime)
			
			base64time = time.time()
			sig_byte = bytes(signature,'utf-8')
			sig_to_verify = base64.b64decode(sig_byte)

			# print("base64 decode time :",time.time()-base64time)

			sha256time = time.time()
			record_h = bytes(str(dns_record.rr[0].rdata),'utf-8')
			target_h=SHA256.new(record_h)

			# print("SHA256time :",time.time()-sha256time)			
			
	else:
		print("Signature get Fail")


	
	if(cert_loc in key_cache_dict):
		# print("cached!")
		publickey_path = key_cache_dict[cert_loc]


	else:
	##not cached
	## get CERT record for PublicKey

		# print("============DNS record (CERT)==============")
		time_cert = time.time()

		cert_q = dnslib.DNSRecord.question(".".join(str(dns_record.questions[0].qname).split(".")[1:]),"CERT")
		TCPanswer = sendTCP(DNSserverIP, cert_q.pack())

		# print("CERT q time :",time.time()-time_cert)

		if(TCPanswer):
			rcode = codecs.encode(TCPanswer[:6],'hex')
			rcode = str(rcode)[11:-1]
			# rcode ==2 is FAIL
			if (int(rcode, 16) == 1):
				print ("Request is not a DNS query. Format Error!")
			else:
				
				time_to_file = time.time()
				# print ("Success!")
				UDPanswer = TCPanswer[2:]
				txt_dd = dnslib.DNSRecord.parse(UDPanswer)
				pkiiii = txt_dd.rr[0].rdata.toZone()
				pemstring = pkiiii.split()[-1]
				
				with open(cert_loc+'.pem', "w") as text_file:
					text_file.write("-----BEGIN CERTIFICATE-----\n")
					text_file.write("%s\n" % pemstring)
					text_file.write("-----END CERTIFICATE-----")

				# print("time cert to file :",time.time()-time_to_file)

				validationtime = time.time()
				try:

					sig_ret = subprocess.check_output("openssl verify -CAfile isrgrootx1.pem -untrusted lets-encrypt-r3.pem "+cert_loc+'.pem',shell=True)
					# print("@@ SIG VAL RESULT :",str(sig_ret[-3:]))
				
					sig_cname = subprocess.check_output("openssl x509 -noout -subject -in "+cert_loc+'.pem',shell=True)
					# print(sig_cname)

				except(Exception):
					print("Certificate validation Fail!!!")
					return

				# if((".".join(str(dns_record.questions[0].qname).split(".")[1:-1])) in str(sig_cname)):
				# 	print("Certificate for",sig_cname,(".".join(str(dns_record.questions[0].qname).split(".")[1:-1])))
				# else:
				# 	print("NO@@@@@@@@@@@@@@@@",sig_cname,".".join(str(dns_record.questions[0].qname).split(".")[1:-1]))

				# print("CERT validation time :",time.time()-validationtime)

				pubkeyouttime = time.time()
				os.system('openssl x509 -pubkey -noout -in '+cert_loc+'.pem > '+ cert_loc+'_pubkey.pem')
				
				
				publickey_path = cert_loc+'_pubkey.pem'
				key_cache_dict[cert_loc] = publickey_path
				# print("Pubkey from CERT time :",time.time()-pubkeyouttime)

		else:
			print("Certificate Get Fail")


	# print("============Validation result==============")
	siganaturevalidationtime = time.time()
	
	# print(publickey_path)
	ff = open(publickey_path,'r+b')
	# print("open key time :",time.time()-siganaturevalidationtime)
	siganaturevalidationtime = time.time()

	public_key = RSA.importKey(ff.read())
	# print("importKey time :",time.time()-siganaturevalidationtime)
	siganaturevalidationtime = time.time()

	pkcs1_15.new(public_key).verify(target_h,sig_to_verify)
	# print("signaturevalidation time :",time.time()-siganaturevalidationtime)
	# print("@#$@  valid  #$@#$@  valid  #$@#$  valid  @#$@#$  valid  @#$#@$  valid  #$#@")
	ff.close()

	
	return True

# a thread to handle DNS request
def handler(data, addr, socket, DNSserverIP):

	start_handler_time = time.time()

	TCPanswer = sendTCP(DNSserverIP, data)

	if TCPanswer:
		rcode = codecs.encode(TCPanswer[:6],'hex')

		rcode = str(rcode)[11:-1]
		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			# print ("Success!")
			# print("A record time :", time.time()-start_handler_time)
			UDPanswer = TCPanswer[2:]
			dd = dnslib.DNSRecord.parse(UDPanswer)
			# print("============DNS record (A)==============")
			# print(dd)
			
			# print("============DNS record (A) end==============")

			#if validation is needed
			# needed=True
			needed=False

			if(needed):
				validate(dd,DNSserverIP)

			socket.sendto(UDPanswer, addr)
			# print("##########  time  ############")
			print(time.time()-start_handler_time)
			# print("########## time end #########")

	else:
		print ("Request is not a DNS query. Format Error!")


	

if __name__ == '__main__':
	DNSserverIP = sys.argv[1]
	port = int(sys.argv[2])
	host = 'localhost'

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	sock.bind((host, port))

	while True:

		data,addr = sock.recvfrom(10240)

		# print(addr)

		_thread.start_new_thread(handler, (data, addr, sock, DNSserverIP))


