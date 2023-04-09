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


	#print("============DNS record (RRSIG)==============")
	rrsig_q = dnslib.DNSRecord.question(dns_query,"RRSIG")

	#fetching RRSIG record first
	TCPanswer = sendTCP(DNSserverIP, rrsig_q.pack())

	if(TCPanswer):
		rcode = codecs.encode(TCPanswer[:6],'hex')
		rcode = str(rcode)[11:-1]

		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:

			UDPanswer = TCPanswer[2:]
			rrsig_parsed = dnslib.DNSRecord.parse(UDPanswer)
			rrsig_record = rrsig_parsed.rr[0].rdata.toZone()

			signature = rrsig_record.split()[-1]
			cert_loc =  rrsig_record.split()[-2]

			sig_byte = bytes(signature,'utf-8')
			#below is the signature to be verified
			sig_to_verify = base64.b64decode(sig_byte)

	else:
		print("Signature get Fail")
	
	#fetching requested DNS record.. in this case, A record
	TCPanswer = sendTCP(DNSserverIP, data)

	if TCPanswer:
		rcode = codecs.encode(TCPanswer[:6],'hex')

		rcode = str(rcode)[11:-1]
		# rcode ==2 is FAIL
		if (int(rcode, 16) == 1):
			print ("Request is not a DNS query. Format Error!")
		else:

			FinalUDPanswer = TCPanswer[2:]
			dns_record = dnslib.DNSRecord.parse(FinalUDPanswer)

	else:
		print ("Request is not a DNS query. Format Error!")

	record_h = bytes(str(dns_record.rr[0].rdata),'utf-8')
	#below is the record to be verified
	target_h = SHA256.new(record_h)

	if(False):
		#this line will be changed to check cached public key
		print("Something Wrong...")
	else:
		#not cached
		
		# get CERT record for PublicKey
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
				cert_parsed = dnslib.DNSRecord.parse(UDPanswer)
				
				for i in range(0,2):
					cert = cert_parsed.rr[i].rdata.toZone()
					#if the keytag is "0", leaf certificate. "1", intermediate certificate.
					if(cert.split()[1]=="0"):
						leaf_pemstring = cert.split()[-1]
					else:
						inter_pemstring = cert.split()[-1]
						
				#leaf certificate will be written as file
				with open(cert_loc+'leaf.pem', "w") as text_file:
					text_file.write("-----BEGIN CERTIFICATE-----\n")
					text_file.write("%s\n" % leaf_pemstring)
					text_file.write("-----END CERTIFICATE-----")
					
				#intermediate certificate will be written as file
				with open(cert_loc+'inter.pem', "w") as text_file:
					text_file.write("-----BEGIN CERTIFICATE-----\n")
					text_file.write("%s\n" % inter_pemstring)
					text_file.write("-----END CERTIFICATE-----")


				try:

					#checking the certificate chain...
					#sig_ret = subprocess.check_output("openssl verify -CAfile isrgrootx1.pem -untrusted lets-encrypt-r3.pem "+cert_loc+'leaf.pem',shell=True)
					sig_ret = subprocess.check_output("openssl verify -CAfile isrgrootx1.pem -untrusted "+cert_loc+'inter.pem'+" "+cert_loc+'leaf.pem',shell=True)
					
					#fetching the cname of the certificate
					sig_cname = subprocess.check_output("openssl x509 -noout -subject -in "+cert_loc+'leaf.pem',shell=True)
					

				except(Exception):
					print("Certificate validation Fail!!!")
					return


				#check the name of certificate
				if(cert_loc[:-1] not in str(sig_cname)):
					print("Certificate name error")
					return


				#extracting public key from the certificate
				os.system('openssl x509 -pubkey -noout -in '+cert_loc+'leaf.pem > '+ cert_loc+'_pubkey.pem')
				
				publickey_path = cert_loc+'_pubkey.pem'

				#caching the public key
				key_cache_dict[cert_loc] = publickey_path

		else:
			print("Certificate Get Fail")
			
		
		#fetching DNSKEY record
		#print("============DNS record (DNSKEY)==============")
		dnskey_q = dnslib.DNSRecord.question(cert_loc,"DNSKEY")
		TCPanswer = sendTCP(DNSserverIP, dnskey_q.pack())

		if(TCPanswer):
			rcode = codecs.encode(TCPanswer[:6],'hex')
			rcode = str(rcode)[11:-1]
			# rcode ==2 is FAIL
			if (int(rcode, 16) == 1):
				print ("Request is not a DNS query. Format Error!")
			else:

				UDPanswer = TCPanswer[2:]
				dnskey_parsed = dnslib.DNSRecord.parse(UDPanswer)
				dnskey_record = dnskey_parsed.rr[0].rdata.toZone()
				pubkey_string = dnskey_record.split()[-1]
			
				f_pubkey_from_file = open(publickey_path,"r") 
				f_pubkey_from_file_string = "".join(f_pubkey_from_file.read().splitlines()[1:-1])
				
				
				if(pubkey_string!=f_pubkey_from_file_string):
					print("!! KEY INVALID !!")
					return

	#validating the records (RRSIG, CERT, DNSKEY)
	#print("============Validation result==============")
	ff = open(publickey_path,'r+b')

	public_key = RSA.importKey(ff.read())

	pkcs1_15.new(public_key).verify(target_h,sig_to_verify)

	#if the signature is valid, send the response to the client
	socket.sendto(FinalUDPanswer, addr)

	ff.close()

	print("time ",time.time()-start_startQuery_time)
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


		_thread.start_new_thread(startQuery, (data, addr, sock, DNSserverIP,dns_query))


