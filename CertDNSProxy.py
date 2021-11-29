import socket
import os
import sys
import struct
import codecs
import _thread
# import dnslib
import dnslib
import binascii
import base64
import subprocess

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
# from certvalidator import CertificateValidator

import time

key_cache_dict = dict()

# convert the UDP DNS query to the TCP DNS query
def getTcpQuery(query):
	message = b'\x00'+ bytes(chr(len(query)),'utf-8') + query
	return message

# send a TCP DNS query to the upstream DNS server
def sendTCP(DNSserverIP, query):
	server = (DNSserverIP, 53)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect(server)
	tcp_query = getTcpQuery(query)
	sock.send(tcp_query)  	
	data = sock.recv(10240)
	return data

# a new thread to handle the UPD DNS request to TCP DNS request

def validate(dns_record,DNSserverIP):
	global key_cache_dict

	publickey_path = ""
	cert_loc = ""
	#find cache first
	domain_name = str(dns_record.questions[0].qname)

	print("============DNS record (TXT)==============")
	txt_q = dnslib.DNSRecord.question(dns_record.questions[0].qname,"TXT")
	# print(txt_q.pack())

	txt_q_time = time.time()

	TCPanswer = sendTCP(DNSserverIP, txt_q.pack())

	print("TXT query time :",time.time()-txt_q_time)


	if(TCPanswer):
		rcode = codecs.encode(TCPanswer[:6],'hex')
		rcode = str(rcode)[11:-1]
		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			print ("Success!")

			signaturegentime = time.time()

			UDPanswer = TCPanswer[2:]
			txt_dd = dnslib.DNSRecord.parse(UDPanswer)
			pkiiii = txt_dd.rr[0].rdata.toZone()
			siglist = pkiiii[1:-1].split('" "')
			# print(siglist)
			# print("@@@@@")
			# return

			# siglist.sort()
			signature_l=["",""]


			for sigs in siglist:
				# print(sigs)
				if(sigs.startswith("CertDNS_Cert")):
					cert_loc = sigs.replace("CertDNS_Cert:","")

				if(sigs.startswith("CertDNS_Base64_A_1")):
					signature_l[0]=(sigs.replace("CertDNS_Base64_A_1:",""))

				if(sigs.startswith("CertDNS_Base64_A_2")):
					signature_l[1]=(sigs.replace("CertDNS_Base64_A_2:",""))		

			signature=signature_l[0]+signature_l[1]
			# print("".join(siganture))

			# for i in range(0,len(siglist)):
			# 	signature = signature + siglist[i].replace("pkidnsbase64_"+str(i+1)+":","")
			
			print("signature generation :",time.time()-signaturegentime)
			
			base64time = time.time()
			# print(signature)

			sig_byte = bytes(signature,'utf-8')
			# print(base64.b64decode(sig_byte))
			# print(base64.b64decode(signature))
			sig_to_verify = base64.b64decode(sig_byte)
			# print(type(sig_to_verify))
			print("base64 decode time :",time.time()-base64time)

			sha256time = time.time()

			record_h = bytes(str(dns_record.rr[0].rdata),'utf-8')
			# print(record_h)


			target_h=SHA256.new(record_h)

			print("SHA256time :",time.time()-sha256time)

			
			
			# print("signaturevalidation time :",time.time()-siganaturevalidationtime)

	else:
		print("Signature get Fail")


	print("============DNS record (CERT)==============")
	if(cert_loc in key_cache_dict):
		print("cached!")
		publickey_path = key_cache_dict[cert_loc]


	else:
	##not cached
	## get CERT record for PublicKey

		time_cert = time.time()

		cert_q = dnslib.DNSRecord.question(cert_loc,"CERT")
		# cert_q = dnslib.DNSRecord.question(dns_record.questions[0].qname,"CERT")
		TCPanswer = sendTCP(DNSserverIP, cert_q.pack())

		print("CERT q time :",time.time()-time_cert)

		if(TCPanswer):
			rcode = codecs.encode(TCPanswer[:6],'hex')
			rcode = str(rcode)[11:-1]
			# rcode ==2 is FAIL
			if (int(rcode, 16) == 1):
				print ("Request is not a DNS query. Format Error!")
			else:
				
				time_to_file = time.time()
				print ("Success!")
				UDPanswer = TCPanswer[2:]
				txt_dd = dnslib.DNSRecord.parse(UDPanswer)
				
				# print(txt_dd)
				pkiiii = txt_dd.rr[0].rdata.toZone()
				pemstring = pkiiii.split()[-1]
				# print(pkiiii.split())
				
				with open(cert_loc+'.pem', "w") as text_file:
					text_file.write("-----BEGIN CERTIFICATE-----\n")
					text_file.write("%s\n" % pemstring)
					text_file.write("-----END CERTIFICATE-----")

				print("time cert to file :",time.time()-time_to_file)

				# readingchainfile = time.time()
				# with open(domain_name+'pem', 'rb') as f:
				# 	end_entity_cert = f.read()
				# with open("lets-encrypt-r3.der", 'rb') as f:
				# 	intermediate_cert = f.read()
				
				# print("reading chain file :",time.time()-readingchainfile)

				# intermediate_certs = list()
				# intermediate_certs.append(intermediate_cert)

				validationtime = time.time()
				try:
					# validator = CertificateValidator(end_entity_cert,intermediate_certs)
					# validator.validate_usage(set(['digital_signature']))
					# os.system("openssl verify -CAfile isrgrootx1.pem -untrusted lets-encrypt-r3.pem "+domain_name+'pem')
					sig_ret = subprocess.check_output("openssl verify -CAfile isrgrootx1.pem -untrusted lets-encrypt-r3.pem "+cert_loc+'.pem',shell=True)
					print("@@ SIG VAL RESULT :",str(sig_ret[-3:]))
					
					sig_cname = subprocess.check_output("openssl x509 -noout -subject -in "+cert_loc+'.pem',shell=True)
					print(sig_cname)
					# cert_cname_list = sig_cname.decode('utf-8').split(' ')[-1][:-1].split('.')
					# domain_name_list = domain_name.split('.')

					#check TLD and SLD

					# for i in range(1,3):
					# 	print(cert_cname_list[-i],domain_name_list[-(i+1)])
					# 	if(cert_cname_list[-i]!=domain_name_list[-(i+1)]):
					# 		print("Certificate cname error!!")
					# 		return

				except(Exception):
					print("Certificate validation Fail!!!")
					return

				print("CERT validation time :",time.time()-validationtime)

				pubkeyouttime = time.time()
				os.system('openssl x509 -pubkey -noout -in '+cert_loc+'.pem > '+ cert_loc+'_pubkey.pem')
				
				
				publickey_path = cert_loc+'_pubkey.pem'
				key_cache_dict[cert_loc] = publickey_path
				print("Pubkey from CERT time :",time.time()-pubkeyouttime)

		else:
			print("Certificate Get Fail")


	print("============Validation result==============")
	siganaturevalidationtime = time.time()
	# try:
	print(publickey_path)
	ff = open(publickey_path,'r+b')
	print("open key time :",time.time()-siganaturevalidationtime)
	siganaturevalidationtime = time.time()

	public_key = RSA.importKey(ff.read())
	print("importKey time :",time.time()-siganaturevalidationtime)
	siganaturevalidationtime = time.time()
	# print(sig_to_verify)
	# print(len(sig_to_verify))
	pkcs1_15.new(public_key).verify(target_h,sig_to_verify)
	print("signaturevalidation time :",time.time()-siganaturevalidationtime)
	print("@#$@  valid  #$@#$@  valid  #$@#$  valid  @#$@#$  valid  @#$#@$  valid  #$#@")
	ff.close()
	# except(ValueError,TypeError):
	# 	print("no valide")

	## get TXT record for signature
	
	
	return True

def handler(data, addr, socket, DNSserverIP):

	start_handler_time = time.time()

	TCPanswer = sendTCP(DNSserverIP, data)
	# print(TCPanswer)
	#print "TCP Answer from server: ", TCPanswer.encode("hex")
	#print ""
	if TCPanswer:
		rcode = codecs.encode(TCPanswer[:6],'hex')
		# print(rcode)
		rcode = str(rcode)[11:-1]
		# print(rcode)
		# rcode ==2 is FAIL
		#print "RCODE: ", rcode
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:
			print ("Success!")
			print("A record time :", time.time()-start_handler_time)
			UDPanswer = TCPanswer[2:]
			dd = dnslib.DNSRecord.parse(UDPanswer)
			print("============DNS record (A)==============")
			print(dd)
			
			print("============DNS record (A) end==============")

			needed=True
			# needed=False

			if(needed):
				validate(dd,DNSserverIP)

			socket.sendto(UDPanswer, addr)
			print("##########  time  ############")
			print(time.time()-start_handler_time)
			print("########## time end #########")

	else:
		print ("Request is not a DNS query. Format Error!")


	

if __name__ == '__main__':
	DNSserverIP = sys.argv[1]
	port = int(sys.argv[2])
	host = 'localhost'
	# try:


	# setup a UDP server to get the UDP DNS request
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

	sock.bind((host, port))

	while True:

		data,addr = sock.recvfrom(10240)

		print(addr)

		_thread.start_new_thread(handler, (data, addr, sock, DNSserverIP))




	# except Exception:
	#     print (Exception)
	#     sock.close()
