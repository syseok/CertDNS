#!/bin/bash

for var in {1..100} 
do
	dig @localhost -p 5757 web.cert-dns.com A
	sleep 30s
done
