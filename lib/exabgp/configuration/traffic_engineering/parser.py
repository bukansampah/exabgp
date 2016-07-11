# encoding: utf-8
"""
traffic_engineering/parser.py

Created by Yannick Le Teigner 2016-06-23.
"""

from exabgp.protocol.family import AFI

from exabgp.protocol.ip import IP
from exabgp.bgp.message.update.attribute import NextHopSelf

from exabgp.bgp.message.update.nlri import LS_UNICAST
from exabgp.bgp.message.update.attribute import Attributes
from exabgp.rib.change import Change


def ls_unicast (tokeniser):
	return Change(
		LS_UNICAST(None,None,None,None,None,None),
		Attributes()
	)


def ls_unicast_local_node (tokeniser):
	value = tokeniser()
	return IP.create(value)


def ls_unicast_remote_node (tokeniser):
	value = tokeniser()
	return IP.create(value)


def ls_unicast_link_local_identifier (tokeniser):
	number = int(tokeniser())
	if number < 0 or number > 0xFFFF:
		raise ValueError('invalid ls_unicast local identifier')
	return number


def ls_unicast_link_remote_identifier (tokeniser):
	number = int(tokeniser())
	if number < 0 or number > 0xFFFF:
		raise ValueError('invalid ls_unicast remote identifier')
	return number


def ls_unicast_ipv4_interface_address (tokeniser):
	value = tokeniser()
	return IP.create(value)


def ls_unicast_ipv4_neighbor_address (tokeniser):
	value = tokeniser()
	return IP.create(value)


def next_hop (tokeniser):
	value = tokeniser()

	if value.lower() == 'self':
		return NextHopSelf(AFI.ipv4)
	return IP.create(value)
