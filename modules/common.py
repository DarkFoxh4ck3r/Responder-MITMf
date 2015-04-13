#! /usr/bin/env python2.7

import re



class CoreVars:

	_instance = None

	def __init__(self):
		self.VERSION           = '2.1.2'
		self.On_Off            = None
		self.SSL_On_Off        = None
		self.SMB_On_Off        = None
		self.SQL_On_Off        = None
		self.FTP_On_Off        = None
		self.POP_On_Off        = None
		self.IMAP_On_Off       = None
		self.SMTP_On_Off       = None
		self.LDAP_On_Off       = None
		self.DNS_On_Off        = None
		self.Krb_On_Off        = None
		self.NumChal           = None
		self.SessionLog        = None
		self.Exe_On_Off        = None
		self.Exec_Mode_On_Off  = None
		self.FILENAME          = None
		self.WPAD_Script       = None
		self.SSLcert           = None
		self.SSLkey            = None
		self.RespondTo         = None
		self.RespondToName     = None
		self.DontRespondTo     = None
		self.DontRespondToName = None
		self.HTMLToServe       = ""
		self.Challenge         = ""
		self.OURIP             = None
		self.LM_On_Off         = None
		self.WPAD_On_Off       = None
		self.Wredirect         = None
		self.NBTNSDomain       = None
		self.Basic             = None
		self.Finger_On_Off     = None
		self.Verbose           = True
		self.Force_WPAD_Auth   = None
		self.AnalyzeMode       = None
		self.INTERFACE         = "Not set"
		self.BIND_TO_Interface = "ALL"

	@staticmethod
	def getInstance():
		if CoreVars._instance == None:
			CoreVars._instance = CoreVars()

		return CoreVars._instance

	def setCoreVars(self, options, config):

		self.On_Off = config['HTTP'].upper()
		self.SSL_On_Off = config['HTTPS'].upper()
		self.SMB_On_Off = config['SMB'].upper()
		self.SQL_On_Off = config['SQL'].upper()
		self.FTP_On_Off = config['FTP'].upper()
		self.POP_On_Off = config['POP'].upper()
		self.IMAP_On_Off = config['IMAP'].upper()
		self.SMTP_On_Off = config['SMTP'].upper()
		self.LDAP_On_Off = config['LDAP'].upper()
		self.DNS_On_Off = "OFF"
		self.Krb_On_Off = config['Kerberos'].upper()
		self.SessionLog = config['SessionLog']
		self.Exe_On_Off = config['HTTP Server']['Serve-Exe'].upper()
		self.Exec_Mode_On_Off = config['HTTP Server']['Serve-Always'].upper()
		self.FILENAME = config['HTTP Server']['Filename']
		self.WPAD_Script = config['HTTP Server']['WPADScript']
		#HTMLToServe = config.get('HTTP Server', 'HTMLToServe')

		self.SSLcert = config['HTTPS Server']['cert']
		self.SSLkey = config['HTTPS Server']['key']

		self.RespondTo = config['RespondTo'].strip().split(",")
		self.RespondToName = config['RespondToName'].strip().split(",")
		self.DontRespondTo = config['DontRespondTo'].strip().split(",")
		self.DontRespondToName = config['DontRespondToName'].strip().split(",")

		self.NumChal = config['Challenge']
		if len(self.NumChal) is not 16:
			sys.exit("[-] The challenge must be exactly 16 chars long.\nExample: -c 1122334455667788\n")

		# Break out challenge for the hexidecimally challenged.  Also, avoid 2 different challenges by accident.
		for i in range(0,len(self.NumChal),2):
			self.Challenge += self.NumChal[i:i+2].decode("hex")

		#Cli options.
		self.OURIP = options.ip_address
		self.LM_On_Off = options.LM_On_Off
		self.WPAD_On_Off = options.WPAD_On_Off
		self.Wredirect = options.Wredirect
		self.NBTNSDomain = options.NBTNSDomain
		self.Basic = options.Basic
		self.Finger_On_Off = options.Finger
		self.Force_WPAD_Auth = options.Force_WPAD_Auth
		self.AnalyzeMode = options.Analyze

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

def IsOnTheSameSubnet(ip, net):
	net = net+'/24'
	ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
	netstr, bits = net.split('/')
	netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
	mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
	return (ipaddr & mask) == (netaddr & mask)

def FindLocalIP(Iface):
	return OURIP