


class WPADProxy():

	def serve_thread_tcp(host, port, handler):
		try:
			server = ThreadingTCPServer((host, port), handler)
			server.serve_forever()
		except Exception, e:
			print "Error starting TCP server on port %s: %s:" % (str(port),str(e))

	#Function name self-explanatory
	def start(on_off):
		if on_off == True:
			t = threading.Thread(name="WPAD", target=serve_thread_tcp, args=("0.0.0.0", 3141, ProxyHandler))
			t.setDaemon(True)
			t.start()
			return t
		if on_off == False:
			return False


class ThreadingTCPServer(ThreadingMixIn, TCPServer):

	allow_reuse_address = 1

	def server_bind(self):
		TCPServer.server_bind(self)
