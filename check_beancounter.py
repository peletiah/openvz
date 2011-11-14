#!/usr/bin/python
# Copyright (C) 2008 Christian Benke
# Distributed under the terms of the GNU General Public License v2
# v0.4 2008-11-26
# Christian Benke <benkokakao  gmail  com>

import string
import pickle
import sys
import getopt
import re
from optparse import OptionParser
import os

veid=''
current_data=dict()
opts=None
beancounter_data=None
picklefilepath='/tmp/check_beancounter_pickledump'

#-------- find the hostname for each veid ---:

def find_veid(veid):
        veid_conf=open('/etc/vz/conf/' + str(veid) + '.conf','r')
	if int(veid) != 0:
		for line in veid_conf:
			if "HOSTNAME" in line:
				quotes=re.compile("\"")
				line=quotes.sub("",line)
				linefeed=re.compile("\n")
				line=linefeed.sub("",line)
				fqdn=re.split('=',line)
				hostname=re.split('\.',fqdn[1])[0]
				return hostname
	else:
		hostname='OpenVZ HN'
		return hostname

# ---------- get hostname of hardware-node
def get_hn_hostname():
	import socket
	hn_hostname=socket.gethostname()
	return hn_hostname

# ---------- send mail in case of a counter-change

def send_mail(count_change,email):
	sendmail = "/usr/lib/sendmail" # sendmail location
	import os
	hn_hostname=get_hn_hostname()
        p = os.popen("%s -t" % sendmail, "w")
	p.write("From: root\n")
        p.write("To: %s\n" % email)
        p.write("Subject: Beancounters change " + str(hn_hostname) + "\n")
        p.write("\n") # blank line separating headers from body
        p.write("The Beancounter-failcnt value of the following veid(s) and resource(s) has \n")
	p.write("increased in the last 5 minutes:\n\n")
        p.write(count_change)
        sts = p.close()
	if sts is not None:
	        print "Sendmail exit status", sts
	
#---------- compare the failcnt-values

def cntcheck(data_read,current_data,veid,fields,count,count_change):
	if data_read and count == True and data_read is not '0': #comparing counters of new data with previous run
		if not data_read.has_key(veid):
			# ignore newly created VEs
			return 0
		if data_read[veid][fields[0]][5] < current_data[veid][fields[0]][5]:
			hostname=find_veid(veid)
			count_change=str(count_change) + str(hostname) + ': ' + str(fields[0]) + ' failcnt has changed from ' + data_read[veid][fields[0]][5] + ' to ' + str(current_data[veid][fields[0]][5]) + '\n'
	return count_change

#---------- compare the current value with barrier/limit value

def barriercheck(data_read,current_data,veid,fields,count,barrier_break):
	if count == False:	#comparing current level with barrier/limit
		if current_data[veid][fields[0]][0] == 'oomguarpages': #for oomguarpages and physpages only the limit-value is relevant
			if int(current_data[veid][fields[0]][1]) > int(current_data[veid][fields[0]][4])*0.9:
				hostname=find_veid(veid)
				barrier_break = str(barrier_break) + str(hostname) + ': ' + str(current_data[veid][fields[0]][0]) + ' '
		elif current_data[veid][fields[0]][0] == 'physpages':
			if int(current_data[veid][fields[0]][1]) > int(current_data[veid][fields[0]][4])*0.9:
				hostname=find_veid(veid)
				barrier_break = str(barrier_break) + str(hostname) + ': ' + str(current_data[veid][fields[0]][0]) + ' '
		else:
			if int(current_data[veid][fields[0]][1]) > int(current_data[veid][fields[0]][3])*0.9:
				hostname=find_veid(veid)
				barrier_break = str(barrier_break) + str(hostname) + ': ' + str(current_data[veid][fields[0]][0]) + ' '
	return barrier_break


#------------ read user_beancounter and handle the result of the comparison subroutines

def compare_data(beancounter_data,data_read,count,email):
	count_change=str()
	barrier_break=str()
	for line in beancounter_data:
		if 'Version' in line or 'uid' in line or 'dummy' in line:
			continue
		else:
			fields=line.split( )
			if len(fields) == 7:
				i=0
				veid=int(fields[0][:-1])
				fields.pop(0) #remove the first element
				current_data[veid]=dict()
				current_data[veid][fields[0]]=fields
			else:
				i=i+1
				current_data[veid][fields[0]]=fields

		# ------ check barrier/limit
			barrier_break=barriercheck(data_read,current_data,veid,fields,count,barrier_break)


		# ------ check failcnt
			count_change=cntcheck(data_read,current_data,veid,fields,count,count_change)

	if barrier_break and count == False:
		print barrier_break
		sys.exit(2)
	elif count == False:
	        print 'All Beancounters OK'
	        sys.exit(0)
	
	if count_change and count == True:
		send_mail(count_change,email)
		return current_data
	elif count == True:
		return current_data
		

# ----- pickle data - read or write

def pickle_data(current_data,action,count,picklefilepath):
	try:
		picklefile = None
		if action == 'write':
			if current_data:
				picklefile=open(picklefilepath,'w')
				pickle.dump(current_data, picklefile)	
				picklefile.close()
				return
			else:
				print 'current_data is empty: ' + str(current_data)
		elif action == 'read':
			picklefile=open(picklefilepath,'r')
			data_read=pickle.load(picklefile)
			picklefile.close()
			if data_read:
				return data_read
			else:
				print 'DATA_READ IS NONE:' + str(data_read)
				return data_read
	except IOError:
		current_data = compare_data(beancounter_data,'0',count, None)
		picklefile=open(picklefilepath,'w')
		pickle.dump(current_data,picklefile)
		picklefile.close()

# ------- print script usage


if __name__ == "__main__":
        parser = OptionParser()
        #parser.add_option("-h", "--help", action="help")
        parser.add_option("-i", action="store_true", dest="count",
                help="Increase - Check if failcnt-values have increased since the last run and send mail if true(Standalone mode), requires -e")
        parser.add_option("-e", action="append", dest="email",
                help="The email address of the warning recipient, required for -i")
        parser.add_option("-c", action="store_false", dest="count",
                help="Current - Check if current value of a resource is higher than barrier/limit(Nagios mode)")





	(options, args) = parser.parse_args()
	count=options.count

	try:
		email=options.email[0]	
	except TypeError:
		email=options.email

	if count == None:
		parser.print_help()
		os._exit(1)
	elif count and email == None:
		parser.print_help()
		os._exit(1)
	

beancounter_data=open('/proc/user_beancounters','r')
data_read=pickle_data(current_data,'read',count,picklefilepath)
current_data = compare_data(beancounter_data,data_read,count,email)
pickle_data(current_data,'write',count,picklefilepath)

