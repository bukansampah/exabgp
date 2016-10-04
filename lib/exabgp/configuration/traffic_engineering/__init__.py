# encoding: utf-8
"""
traffic_engineering/__init__.py

Created by Yannick Le Teigner 2016-06-23.
"""

from exabgp.configuration.traffic_engineering.ls_unicast import ParseLSUNICAST

from exabgp.bgp.message.update.nlri import LS_UNICAST
from exabgp.bgp.message.update.attribute import Attributes
from exabgp.rib.change import Change


class ParseTrafficEngineering (ParseLSUNICAST):
	syntax = \
		'ls_unicast %s;\n' % ' '.join(ParseLSUNICAST.definition)

	action = dict(ParseLSUNICAST.action)

	name = 'traffic_engineering'

	def __init__ (self, tokeniser, scope, error, logger):
		ParseLSUNICAST.__init__(self,tokeniser,scope,error,logger)

	def clear (self):
		return True

	def pre (self):
		self.scope.to_context()
		return True

	def post (self):
		routes = self.scope.pop(self.name)
		if routes:
			self.scope.extend('routes',routes)
		return True


@ParseTrafficEngineering.register('ls_unicast','append-name')
def ls_unicast (tokeniser):
	change = Change(
		LS_UNICAST(None,None,None,None,None,None,None),
		Attributes()
	)

	while True:
		command = tokeniser()

		if not command:
			break

		action = ParseLSUNICAST.action[command]

		if 'nlri-set' in action:
			change.nlri.assign(ParseLSUNICAST.assign[command],ParseTrafficEngineering.known[command](tokeniser))
		elif 'attribute-add' in action:
			change.attributes.add(ParseTrafficEngineering.known[command](tokeniser))
		elif action == 'nexthop-and-attribute':
			nexthop,attribute = ParseLSUNICAST.known[command](tokeniser)
			change.nlri.nexthop = nexthop
			change.attributes.add(attribute)
		else:
			raise ValueError('ls_unicast: unknown command "%s"' % command)

	return change
