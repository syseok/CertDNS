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

# UDP to TCP
def getTcpQuery(query):
	message = b'\x00'+ bytes(chr(len(query)),'utf-8') + query
	return message

# query to DNS server
def sendTCP(DNSserverIP, query):
	server = (DNSserverIP, 53)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server)
	tcp_query = getTcpQuery(query)
	sock.send(tcp_query)  	
	data = sock.recv(10240)
	return data


# a thread to handle DNS request
def startQuery(data, addr, socket, DNSserverIP,dns_query):

	start_startQuery_time = time.time()
	

	global key_cache_dict

	publickey_path = ""
	cert_loc = ""

	#find cache first
	#domain_name = str(dns_record.questions[0].qname)
	
	#print("querying",dns_query)

	#print("============DNS record (RRSIG)==============")
	txt_q = dnslib.DNSRecord.question(dns_query,"RRSIG")
	#print(txt_q.pack())
	#txt_q_time = time.time()
	#print("$$$$$$$$$$ to",DNSserverIP)
	TCPanswer = sendTCP(DNSserverIP, txt_q.pack())
	# print("TXT query time :",time.time()-txt_q_time)


	if(TCPanswer):
		rcode = codecs.encode(TCPanswer[:6],'hex')
		rcode = str(rcode)[11:-1]

		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			#print ("Success!")

			#signaturegentime = time.time()

			UDPanswer = TCPanswer[2:]
			#print(UDPanswer)
			txt_dd = dnslib.DNSRecord.parse(UDPanswer)
			#print("Parsed: ",txt_dd)
			pkiiii = txt_dd.rr[0].rdata.toZone()
			#print("RRSIG from Resolver : ",pkiiii.split())
			signature = pkiiii.split()[-1]
			cert_loc =  pkiiii.split()[-2]
			#siglist = pkiiii[1:-1].split('" "')
			#signature_l=["",""]


			#for sigs in siglist:
			#	if(sigs.startswith("CertDNS_Base64_A_1")):
			#		signature_l[0]=(sigs.replace("CertDNS_Base64_A_1:",""))
	
			#	if(sigs.startswith("CertDNS_Base64_A_2")):
			#		signature_l[1]=(sigs.replace("CertDNS_Base64_A_2:",""))		

			#signature=signature_l[0]+signature_l[1]

			# print("signature generation :",time.time()-signaturegentime)
			
			#base64time = time.time()
			sig_byte = bytes(signature,'utf-8')
			sig_to_verify = base64.b64decode(sig_byte)

			# print("base64 decode time :",time.time()-base64time)

			#sha256time = time.time()
			#record_h = bytes(str(dns_record.rr[0].rdata),'utf-8')
			#target_h=SHA256.new(record_h)

			# print("SHA256time :",time.time()-sha256time)			
			
	else:
		print("Signature get Fail")
	
	


	TCPanswer = sendTCP(DNSserverIP, data)

	if TCPanswer:
		rcode = codecs.encode(TCPanswer[:6],'hex')

		rcode = str(rcode)[11:-1]
		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			#print ("Success!")
			#print("A record time :", time.time()-start_startQuery_time)
			FinalUDPanswer = TCPanswer[2:]
			dns_record = dnslib.DNSRecord.parse(FinalUDPanswer)
			#print("============DNS record (A)==============")
			#print(dns_record)
			
			#print("============DNS record (A) end==============")



	else:
		print ("Request is not a DNS query. Format Error!")





	record_h = bytes(str(dns_record.rr[0].rdata),'utf-8')
	target_h=SHA256.new(record_h)



	
	if(cert_loc in key_cache_dict):
		# print("cached!")
		publickey_path = key_cache_dict[cert_loc]


	else:
	##not cached
	## get CERT record for PublicKey

		#print("============DNS record (CERT)==============")
		time_cert = time.time()

		cert_q = dnslib.DNSRecord.question(cert_loc,"CERT")
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
				#print(pemstring)
				#print("cert_loc is",cert_loc)
				with open(cert_loc+'.pem', "w") as text_file:
					text_file.write("-----BEGIN CERTIFICATE-----\n")
					text_file.write("%s\n" % pemstring)
					text_file.write("-----END CERTIFICATE-----")

				# print("time cert to file :",time.time()-time_to_file)

				# validationtime = time.time()
				try:

					#
					sig_ret = subprocess.check_output("openssl verify -CAfile isrgrootx1.pem -untrusted lets-encrypt-r3.pem "+cert_loc+'.pem',shell=True)
					# print("@@ SIG VAL RESULT :",str(sig_ret[-3:]))
				
					sig_cname = subprocess.check_output("openssl x509 -noout -subject -in "+cert_loc+'.pem',shell=True)
					# print(sig_cname)

				except(Exception):
					print("Certificate validation Fail!!!")
					return


				#check the name of certificate
				if((".".join(str(dns_record.questions[0].qname).split(".")[1:-1])) not in str(sig_cname)):
					print("Certificate name error")
					return
				#else:
					#print("Certificate for",sig_cname,(".".join(str(dns_record.questions[0].qname).split(".")[1:-1])))

				# print("CERT validation time :",time.time()-validationtime)

				# pubkeyouttime = time.time()
				os.system('openssl x509 -pubkey -noout -in '+cert_loc+'.pem > '+ cert_loc+'_pubkey.pem')
				
				
				publickey_path = cert_loc+'_pubkey.pem'
				key_cache_dict[cert_loc] = publickey_path
				# print("Pubkey from CERT time :",time.time()-pubkeyouttime)

		else:
			print("Certificate Get Fail")
			
		
		
		#print("============DNS record (DNSKEY)==============")
		time_cert = time.time()

		dnskey_q = dnslib.DNSRecord.question(cert_loc,"DNSKEY")
		TCPanswer = sendTCP(DNSserverIP, dnskey_q.pack())

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
				pubkey_string = pkiiii.split()[-1]
				#print("from DNSKEY",pubkey_string)
				f_pubkey_from_file = open(publickey_path,"r") 
				f_pubkey_from_file_string = "".join(f_pubkey_from_file.read().splitlines()[1:-1])
				#print("from CERT",(f_pubkey_from_file_string))
				
				if(pubkey_string!=f_pubkey_from_file_string):
					print("!! KEY INVALID !!")
					return


	#print("============Validation result==============")
	# siganaturevalidationtime = time.time()
	
	#print(publickey_path)
	ff = open(publickey_path,'r+b')
	# print("open key time :",time.time()-siganaturevalidationtime)
	# siganaturevalidationtime = time.time()

	public_key = RSA.importKey(ff.read())
	# print("importKey time :",time.time()-siganaturevalidationtime)
	# siganaturevalidationtime = time.time()

	pkcs1_15.new(public_key).verify(target_h,sig_to_verify)
	# print("signaturevalidation time :",time.time()-siganaturevalidationtime)
	
	#print("@#$@  valid  #$@#$@  valid  #$@#$  valid  @#$@#$  valid  @#$#@$  valid  #$#@")
	socket.sendto(FinalUDPanswer, addr)
	ff.close()
	

	
	print("time :",time.time()-start_startQuery_time)
	return True

	
	
	

	

if __name__ == '__main__':
	DNSserverIP = sys.argv[1]
	port = int(sys.argv[2])
	dns_query = sys.argv[3]
	host = 'localhost'

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	sock.bind((host, port))

	while True:

		data,addr = sock.recvfrom(1024)

		#print(addr)

		_thread.start_new_thread(startQuery, (data, addr, sock, DNSserverIP,dns_query))


