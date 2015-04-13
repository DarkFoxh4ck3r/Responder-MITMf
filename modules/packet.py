#! /usr/bin/env python2.7

#Packet class handling all packet generation (see odict.py).
from odict import OrderedDict

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