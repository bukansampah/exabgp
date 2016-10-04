# encoding: utf-8
"""
ls_unicast.py

Created by Yannick Le Teigner 2016-06-23.
"""

import socket
import struct
from struct import unpack
from struct import pack
from exabgp.protocol.ip import IP
from exabgp.protocol.family import AFI
from exabgp.protocol.family import SAFI
from exabgp.bgp.message.direction import OUT
from exabgp.bgp.message.notification import Notify
from exabgp.bgp.message.update.nlri.nlri import NLRI
from exabgp.bgp.message.update.nlri.qualifier import RouteDistinguisher


def _unique ():
	value = 0
	while True:
		yield value
		value += 1

unique = _unique()


@NLRI.register(AFI.traffic_engineering,SAFI.ls_unicast)
class LS_UNICAST (NLRI):

	__slots__ = ['action','nexthop','local_node','protocol','remote_node',
			'link_local_identifier','link_remote_identifier',
			'ipv4_interface_address','ipv4_neighbor_address', 'unique']

	def __init__ (self, local_node, protocol, remote_node, link_local_identifier, link_remote_identifier, ipv4_interface_address, ipv4_neighbor_address):
		NLRI.__init__(self,AFI.traffic_engineering,SAFI.ls_unicast)
		self.action = OUT.ANNOUNCE
		self.nexthop = None
		self.local_node = local_node
		self.protocol = protocol
		self.remote_node = remote_node
		self.link_local_identifier = link_local_identifier
		self.link_remote_identifier = link_remote_identifier
		self.ipv4_interface_address = ipv4_interface_address
		self.ipv4_neighbor_address = ipv4_neighbor_address
		self.unique = unique.next()

	def __eq__ (self,other):
		return self.nexthop == other.nexthop \
			and self.local_node == other.local_node  # TODO: YLT

	def index (self):
		return self.pack()

	def assign (self, name, value):
		setattr(self,name,value)

	def pack (self, negotiated=None):
		if self.link_local_identifier==None: # Node NLRI
			# FIXME YLT: This is horrible, needs to be addressed
			msg = ''
			if self.protocol==3: # OSPF
				msg += pack(	# LOCAL NODE TLV
					'!HHHHIHHIHHI',
					256, # Type (Node)
					24,  # Length,
					512, # AS TLV
					4,   # AS TLV Length
					100, # AS TLV ID
					514, # OSPF AREA ID TLV
					4,   # AREA ID TLV Length
					0x0, # AREA ID TLV ID
					515, # IGP ROUTER ID TLV
					4,   # IGP ROUTER ID TLV Length
					struct.unpack("!L", socket.inet_aton(self.local_node._string))[0],   # IGP ROUTER ID TLV ID
				)
				length = 37
			else:
				msg += pack(	# LOCAL NODE TLV
					'!HHHHIHHI',
					256, # Type (Node)
					16,  # Length,
					512, # AS TLV
					4,   # AS TLV Length
					100, # AS TLV ID
					515, # IGP ROUTER ID TLV
					4,   # IGP ROUTER ID TLV Length
					struct.unpack("!L", socket.inet_aton(self.local_node._string))[0],   # IGP ROUTER ID TLV ID
				)
				length = 29
			header = '%s%s%s%s' % (
				'\x00\x01',  # Node NLRI
				pack('!H', length), # FIXME: length:37 (29 in ISIS)
				pack("!B", self.protocol), #'\x03',	  # Protocol ID Unknown (0), ospf 3
				'\x00\x00\x00\x00\x00\x00\x00\x00' # Identifier 0->L3, 1->Optical topo
			)
			msg = header + msg
			return msg
		else:
			return '%s%s%s%s%s%s%s' % (
				'\x00\x02',  # Link NLRI
				'\x00\x51',  # FIXME: length: 81
				'\x03',	  # Protocol ID Unknown (0)
				'\x00\x00\x00\x00\x00\x00\x00\x00', # Identifier 0->L3, 1->Optical topo
				pack(	# LOCAL NODE TLV
					'!HHHHIHHIHHI',
					256, # Type (Node)
					24,  # Length,
					512, # AS TLV
					4,   # AS TLV Length
					100,   # AS TLV ID
					#513, # BGP-LS TLV
					#4,   # BGP-LS TLV Length
					#16843009,   # BGP-LS TLV ID
					514, # AREA ID TLV
					4,   # AREA ID TLV Length
					0x0,   # AREA ID TLV ID
					515, # IGP ROUTER ID TLV
					4,   # IGP ROUTER ID TLV Length
					struct.unpack("!L", socket.inet_aton(self.local_node._string))[0],   # IGP ROUTER ID TLV ID
				),
				pack(	# REMOTE NODE TLV
					'!HHHHIHHIHHI',
					257, # Type (Node)
					24,  # Length,
					512, # AS TLV
					4,   # AS TLV Length
					100,   # AS TLV ID
					#513, # BGP-LS TLV
					#4,   # BGP-LS TLV Length
					#16843009,   # BGP-LS TLV ID
					514, # AREA ID TLV
					4,   # AREA ID TLV Length
					0x0,   # AREA ID TLV ID
					515, # IGP ROUTER ID TLV
					4,   # IGP ROUTER ID TLV Length
					struct.unpack("!L", socket.inet_aton(self.remote_node._string))[0],   # IGP ROUTER ID TLV ID
				),
				pack(	# LINK DESCRIPTOR TLV
					'!HHIHHI',
					#258, # Link local/remote ID TLV
					#8,  # Length,
					#self.link_local_identifier, # AS TLV
					#self.link_remote_identifier, # AS TLV
					259, # IPV4 INTF ADDRESS TLV
					4,  # Length,
					struct.unpack("!L", socket.inet_aton(self.ipv4_interface_address._string))[0],
					260, # IPV4 REMOTE ADDRESS TLV
					4,  # Length,
					struct.unpack("!L", socket.inet_aton(self.ipv4_neighbor_address._string))[0],
				)
			)

	# XXX: FIXME: we need an unique key here.
	# XXX: What can we use as unique key ?
	def json (self):
		content = ', '.join([
			'"local_node": %s' % self.local_node,
			'"protocol": %s' % self.protocol,
			'"remote_node": %s' % self.remote_node,
			'"link_local_identifier": %s' % self.link_local_identifier,
			'"link_remote_identifier": %s' % self.link_remote_identifier,
			'"ipv4_interface_address": %s' % self.ipv4_interface_address,
			'"ipv4_neighbor_address": %s' % self.ipv4_neighbor_address,
		])
		return '{ %s }' % (content)

	def extensive (self):
		return "ls_unicast local_node %s protocol %s remote_node %s link_local_identifier %s link_remote_identifier %s ipv4_interface_address %s ipv4_neighbor_address %s %s" % (
			self.local_node,
			self.protocol,
			self.remote_node,
			self.link_local_identifier,
			self.link_remote_identifier,
			self.ipv4_interface_address,
			self.ipv4_neighbor_address,
			'' if self.nexthop is None else 'next-hop %s' % self.nexthop,
		)

	def __str__ (self):
		return self.extensive()

	@classmethod
	def unpack_nlri (cls, afi, safi, bgp, action, addpath):
		# TODO: YLT
		pass
