# encoding: utf-8
"""
linkstate.py

Created by Yannick Le Teigner on 2016-06-23.
"""

import socket
from struct import pack
from struct import unpack

from exabgp.bgp.message.update.attribute.attribute import Attribute


# ========================================================= Link State (29)
#

@Attribute.register()
class LinkState (Attribute):
	ID = Attribute.CODE.LINK_STATE
	FLAG = Attribute.Flag.OPTIONAL
	CACHING = True

	__slots__ = ['linkstate','_packed']
	tlv_types = [
		[1026, 'nn'],
		[1027, 'iai'],
		[1028, 'lridv4'],
		[1089, 'mlb'],
		[1090, 'mrlb'],
		[1091, 'ub'],
		[1092, 'tem'],
		[1095, 'im']]

	def __init__ (self, tlvs, packed=None):
		self.tlvs = {}
		#self._packed = self._attribute(packed if packed is not None else pack('!L',tlvs))
		for tlv in tlvs:
			typ = tlv[:tlv.find(":")]
			val = tlv[tlv.find(":")+1:]
			self.tlvs[typ] = val
		enc = ""
		# it is important for the TLVs to be ordered (RFC7752 3.1)
		for tlv_id, tlv_type in self.tlv_types:
			if tlv_type in self.tlvs.keys():
				val = self.tlvs[tlv_type]
				if tlv_type=="nn":  # Node name
					enc += "%s%s%s" % (
						'\x04\x02', # 1026
						pack('!H', len(val)),
						val)
				elif tlv_type=="iai":  # ISIS Area Identifier
					enc += "%s%s%s" % (
						'\x04\x03', # 1027
						pack('!H', len(val.decode("hex"))),
						val.decode("hex"))
				elif tlv_type=="lridv4":  # local RID v4
					enc += "%s%s%s" % (
						'\x04\x04', # 1028
						'\x00\x04', # Length
						socket.inet_aton(val))
				elif tlv_type=="mlb":  # Maximum Link Bandwidth
					enc += "%s%s%s" % (
						'\x04\x41', # 1089
						'\x00\x04', # length
						pack('!f', int(val)/8))
				elif tlv_type=="mrlb":  # Maximum Reservable Link Bandwidth
					enc += "%s%s%s" % (
						'\x04\x42', # 1090
						'\x00\x04', # length
						pack('!f', int(val)/8))
				elif tlv_type=="ub":  # Unreserved Bandwidth
					enc += "%s%s" % (
						'\x04\x43', # 1091
						'\x00\x20') # length
					for v in val.split(':'):
						enc += "%s" % pack('!f', int(v)/8)
				elif tlv_type=="tem":  # TE default metric
					enc += "%s%s%s" % (
						'\x04\x44', # 1092
						'\x00\x04', # length
						pack('!I', int(val)))
				elif tlv_type=="im":  # IGP metric
					enc += "%s%s%s" % (
						'\x04\x47', # 1095
						'\x00\x03', # length
						pack('!I', int(val))[1:])
		self._packed = self._attribute(enc)

	def __eq__ (self, other):
		return \
			self.ID == other.ID and \
			self.FLAG == other.FLAG and \
			self.tlvs == other.tlvs

	def __ne__ (self, other):
		return not self.__eq__(other)

	def pack (self, negotiated=None):
		return self._packed

	def __len__ (self):
		if len(tlvs)==1:
			return 75
		else:
			return 22

	def __repr__ (self):
		return str(self.tlvs)

	@classmethod
	def unpack (cls, data, negotiated):
		return cls(unpack('!L',data)[0],data)
