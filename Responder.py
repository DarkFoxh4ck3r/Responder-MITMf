#! /usr/bin/env python
# NBT-NS/LLMNR Responder
# Created by Laurent Gaffie
# Copyright (C) 2014 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
from SocketServer import TCPServer, UDPServer, ThreadingMixIn, StreamRequestHandler, BaseRequestHandler, BaseServer
from Fingerprint import RunSmbFinger, OsNameClientVersion
from odict import OrderedDict
from socket import inet_aton
from random import randrange
from SMBPackets import *
from SQLPackets import *
from RAPLANMANPackets import *
from HTTPPackets import *
from HTTPProxy import *
from LDAPPackets import *
from SMTPPackets import *
from IMAPPackets import *
from OpenSSL import SSL

import sys
import struct
import SocketServer
import logging
import re
import socket
import threading
import Fingerprint
import random
import os
import ConfigParser
import BaseHTTPServer
import select
import urlparse
import zlib
import string
import time
"""
import logging

formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
responder_logger = logging.getLogger('responder')
fileHandler = logging.FileHandler("./logs/responder/Responder-Session.log")
fileHandler.setFormatter(formatter)
responder_logger.addHandler(fileHandler)

Log2Filename = "./logs/responder/LLMNR-NBT-NS.log"
logger2 = logging.getLogger('LLMNR/NBT-NS')
logger2.addHandler(logging.FileHandler(Log2Filename,'a'))

AnalyzeFilename = "./logs/responder/Analyze-LLMNR-NBT-NS.log"
logger3 = logging.getLogger('Analyze LLMNR/NBT-NS')
logger3.addHandler(logging.FileHandler(AnalyzeFilename,'a'))


from modules.llmnr.LLMNRPoisoner import LLMNRPoisoner
from modules.common import IsOnTheSameSubnet, CoreVars

class ResponderMITMf():

	''' Main class thats kicks off Responder'''

	def __init__(self, options, config):
		CoreVars.getInstance().setCoreVars(options, config)

	def AnalyzeICMPRedirect(self, AnalyzeMode):
		result = False
		if AnalyzeMode:
			result = self.IsICMPRedirectPlausible(OURIP)

		return result

	def IsICMPRedirectPlausible(self, IP):
		result = []
		dnsip = []
		for line in file('/etc/resolv.conf', 'r'):
			ip = line.split()
			if len(ip) < 2:
			   continue
			if ip[0] == 'nameserver':
				dnsip.extend(ip[1:])
		for x in dnsip:
			if x !="127.0.0.1" and IsOnTheSameSubnet(x,IP) == False:
				result.append("[Analyze mode: ICMP] You can ICMP Redirect on this network. This workstation (%s) is not on the same subnet than the DNS server (%s). Use python Icmp-Redirect.py for more details."%(IP, x))
			else:
				pass

		return result

	def printDebugInfo(self):
		start_message = "|  |_ Responder will redirect requests to: %s\n" % OURIP
	   #start_message += "|  |_ Responder is bound to interface: %s\n" % INTERFACE
		start_message += "|  |_ Challenge set: %s\n" % NumChal
		start_message += "|  |_ WPAD Proxy Server: %s\n" % WPAD_On_Off
	   #start_message += "|  |_ WPAD script loaded: %s\n" % WPAD_Script
		start_message += "|  |_ HTTP Server: %s\n" % On_Off
		start_message += "|  |_ HTTPS Server: %s\n" % SSL_On_Off
		start_message += "|  |_ SMB Server: %s\n" % SMB_On_Off
		start_message += "|  |_ SMB LM support: %s\n" % LM_On_Off
		start_message += "|  |_ Kerberos Server: %s\n" % Krb_On_Off
		start_message += "|  |_ SQL Server: %s\n" % SQL_On_Off
		start_message += "|  |_ FTP Server: %s\n" % FTP_On_Off
		start_message += "|  |_ IMAP Server: %s\n" % IMAP_On_Off
		start_message += "|  |_ POP3 Server: %s\n" % POP_On_Off
		start_message += "|  |_ SMTP Server: %s\n" % SMTP_On_Off
	   #start_message += "|  |_ DNS Server: %s\n" % DNS_On_Off
		start_message += "|  |_ LDAP Server: %s\n" % LDAP_On_Off
		start_message += "|  |_ FingerPrint hosts: %s\n" % Finger_On_Off
		start_message += "|  |_ Serving Executable via HTTP&WPAD: %s\n" % Exe_On_Off
		start_message += "|  |_ Always Serving a Specific File via HTTP&WPAD: %s" % Exec_Mode_On_Off
		
		print start_message

	def start(self):

		LLMNRPoisoner().start()

	"""
		Is_FTP_On(FTP_On_Off)
		Is_HTTP_On(On_Off)
		Is_HTTPS_On(SSL_On_Off)
		Is_WPAD_On(WPAD_On_Off)
		Is_Kerberos_On(Krb_On_Off)
		Is_SMB_On(SMB_On_Off)
		Is_SQL_On(SQL_On_Off)
		Is_LDAP_On(LDAP_On_Off)
		Is_DNS_On(DNS_On_Off)
		Is_POP_On(POP_On_Off)
		Is_SMTP_On(SMTP_On_Off)
		Is_IMAP_On(IMAP_On_Off)
		#Browser listener loaded by default
		t1 = threading.Thread(name="Browser", target=serve_thread_udp, args=("0.0.0.0", 138, Browser))
		## Poisoner loaded by default, it's the purpose of this tool...
		t2 = threading.Thread(name="MDNS", target=serve_thread_udp_MDNS, args=("0.0.0.0", 5353, MDNS)) #MDNS
		t3 = threading.Thread(name="KerbUDP", target=serve_thread_udp, args=("0.0.0.0", 88, KerbUDP)) 
		t4 = threading.Thread(name="NBNS", target=serve_thread_udp, args=("0.0.0.0", 137,NB)) #NBNS
		t5 = threading.Thread(name="LLMNR", target=serve_thread_udp_LLMNR, args=("0.0.0.0", 5355, LLMNR)) #LLMNR

		for t in [t1, t2, t3, t4, t5]:
			t.setDaemon(True)
			t.start()
	"""