# encoding: utf-8
"""
parse_ls_unicast.py

Created by Yannick Le Teigner 2016-06-23.
"""

from exabgp.configuration.core import Section

from exabgp.configuration.static.parser import attribute
from exabgp.configuration.static.parser import origin
from exabgp.configuration.static.parser import med
from exabgp.configuration.static.parser import as_path
from exabgp.configuration.static.parser import local_preference
from exabgp.configuration.static.parser import link_state
from exabgp.configuration.static.parser import atomic_aggregate
from exabgp.configuration.static.parser import aggregator
from exabgp.configuration.static.parser import originator_id
from exabgp.configuration.static.parser import cluster_list
from exabgp.configuration.static.parser import community
from exabgp.configuration.static.parser import extended_community
from exabgp.configuration.static.parser import name as named
from exabgp.configuration.static.parser import split
from exabgp.configuration.static.parser import watchdog
from exabgp.configuration.static.parser import withdraw

from exabgp.configuration.static.mpls import route_distinguisher

from exabgp.configuration.traffic_engineering.parser import ls_unicast
from exabgp.configuration.traffic_engineering.parser import ls_unicast_local_node
from exabgp.configuration.traffic_engineering.parser import ls_unicast_remote_node
from exabgp.configuration.traffic_engineering.parser import ls_unicast_link_local_identifier
from exabgp.configuration.traffic_engineering.parser import ls_unicast_link_remote_identifier
from exabgp.configuration.traffic_engineering.parser import ls_unicast_ipv4_interface_address
from exabgp.configuration.traffic_engineering.parser import ls_unicast_ipv4_neighbor_address
from exabgp.configuration.traffic_engineering.parser import next_hop


class ParseLSUNICAST (Section):
	definition = [
		'local_node <local node ip; ipv4>',
		'remote_node <remote node ip; ipv4>',
		'link_local_identifier <link local identifier; integer>',
		'link_remote_identifier <link remote identifier; interger>',
		'ipv4_interface_address <local address; ipv4>',
		'ipv4_neighbor_address <neighbor address; ipv4>',

		'next-hop <ip>',
		'med <16 bits number>',
		'route-distinguisher|rd <ipv4>:<port>|<16bits number>:<32bits number>|<32bits number>:<16bits number>',
		'origin IGP|EGP|INCOMPLETE',
		'as-path [ <asn>.. ]',
		'local-preference <16 bits number>',
		'link-state <16 bits number>',
		'atomic-aggregate',
		'community <16 bits number>',
		'extended-community target:<16 bits number>:<ipv4 formated number>',
		'originator-id <ipv4>',
		'cluster-list <ipv4>',
		'label <15 bits number>',
		'attribute [ generic attribute format ]'
		'name <mnemonic>',
		'split /<mask>',
		'watchdog <watchdog-name>',
		'withdraw',
	]

	syntax = \
		'ls_unicast {\n  %s\n}' % ' ;\n  '.join(definition)

	known = {
		'rd':                 route_distinguisher,
		'attribute':          attribute,
		'next-hop':           next_hop,
		'origin':             origin,
		'med':                med,
		'as-path':            as_path,
		'local-preference':   local_preference,
		'link-state':         link_state,
		'atomic-aggregate':   atomic_aggregate,
		'aggregator':         aggregator,
		'originator-id':      originator_id,
		'cluster-list':       cluster_list,
		'community':          community,
		'extended-community': extended_community,
		'name':               named,
		'split':              split,
		'watchdog':           watchdog,
		'withdraw':           withdraw,
		'local_node':             ls_unicast_local_node,
		'remote_node':            ls_unicast_remote_node,
		'link_local_identifier':  ls_unicast_link_local_identifier,
		'link_remote_identifier': ls_unicast_link_remote_identifier,
		'ipv4_interface_address': ls_unicast_ipv4_interface_address,
		'ipv4_neighbor_address':  ls_unicast_ipv4_neighbor_address,
	}

	action = {
		'attribute':           'attribute-add',
		'origin':              'attribute-add',
		'med':                 'attribute-add',
		'as-path':             'attribute-add',
		'local-preference':    'attribute-add',
		'link-state':          'attribute-add',
		'atomic-aggregate':    'attribute-add',
		'aggregator':          'attribute-add',
		'originator-id':       'attribute-add',
		'cluster-list':        'attribute-add',
		'community':           'attribute-add',
		'extended-community':  'attribute-add',
		'name':                'attribute-add',
		'split':               'attribute-add',
		'watchdog':            'attribute-add',
		'withdraw':            'attribute-add',
		'next-hop':               'nlri-set',
		'local_node':             'nlri-set',
		'remote_node':            'nlri-set',
		'link_local_identifier':  'nlri-set',
		'link_remote_identifier': 'nlri-set',
		'ipv4_interface_address': 'nlri-set',
		'ipv4_neighbor_address':  'nlri-set',
	}

	assign = {
		'next-hop':            'nexthop',
		'rd':                  'rd',
		'route-distinguisher': 'rd',
		'local_node':             'local_node',
		'remote_node':            'remote_node',
		'link_local_identifier':  'link_local_identifier',
		'link_remote_identifier': 'link_remote_identifier',
		'ipv4_interface_address': 'ipv4_interface_address',
		'ipv4_neighbor_address':  'ipv4_neighbor_address',
	}

	name = 'traffic_engineering/ls_unicast'

	def __init__ (self, tokeniser, scope, error, logger):
		Section.__init__(self,tokeniser,scope,error,logger)

	def clear (self):
		pass

	def pre (self):
		self.scope.set(self.name,ls_unicast(self.tokeniser.iterate))
		return True

	def post (self):
		if not self._check():
			return False
		# self.scope.to_context()
		route = self.scope.pop(self.name)
		if route:
			self.scope.append('routes',route)
		return True

	def _check (self):
		nlri = self.scope.get(self.name).nlri

		if nlri.nexthop is None:
			return self.error.set('ls_unicast next-hop missing')
		if nlri.local_node is None:
			return self.error.set('ls_unicast local_node missing')
		return True

	def check (change):
		return True
