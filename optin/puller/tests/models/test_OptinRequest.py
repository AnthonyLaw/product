import unittest

from symbolchain.CryptoTypes import Hash256, PublicKey
from symbolchain.nem.Network import Address

from puller.models.OptinRequest import OptinRequest, OptinRequestError

HASH_1 = 'FA650B75CC01187E004FCF547796930CC95D9CF55E6E6188FC7D413526A840FA'
HASH_2 = '1A4FAB268E43DECAAF87D548691651774D8508DDC4CC6D25BEAC8D6AEBF69BEF'
HEIGHT = 1234567890625
PUBLIC_KEY_1 = '138F8ECE0F01DC7CCD196F2C6249CBB78CF2822D23376C96C949DF859D5A0FC5'
PUBLIC_KEY_2 = '1BB7ACCACE4C2527F425B2156C676105DF013404F7FA1F169377CA05393AECBE'
NEM_ADDRESS = 'NBMUCRGBBF7LIVQWS2AHYOEAM7NMSDHJX7SQ54GJ'


class OptinRequestTest(unittest.TestCase):
	def test_can_create_request_regular(self):
		# Act:
		request = OptinRequest(Address(NEM_ADDRESS), HEIGHT, Hash256(HASH_1), Hash256(HASH_2), {'type': 100, 'destination': PUBLIC_KEY_1})

		# Assert:
		self.assertEqual(Address(NEM_ADDRESS), request.address)
		self.assertEqual(HEIGHT, request.optin_transaction_height)
		self.assertEqual(Hash256(HASH_1), request.optin_transaction_hash)
		self.assertEqual(Hash256(HASH_2), request.payout_transaction_hash)
		self.assertEqual(PublicKey(PUBLIC_KEY_1), request.destination_public_key)
		self.assertEqual(None, request.multisig_public_key)
		self.assertEqual(False, request.is_error)

	def test_can_create_request_regular_without_payout_transaction_hash(self):
		# Act:
		request = OptinRequest(Address(NEM_ADDRESS), HEIGHT, Hash256(HASH_1), None, {'type': 100, 'destination': PUBLIC_KEY_1})

		# Assert:
		self.assertEqual(Address(NEM_ADDRESS), request.address)
		self.assertEqual(HEIGHT, request.optin_transaction_height)
		self.assertEqual(Hash256(HASH_1), request.optin_transaction_hash)
		self.assertEqual(None, request.payout_transaction_hash)
		self.assertEqual(PublicKey(PUBLIC_KEY_1), request.destination_public_key)
		self.assertEqual(None, request.multisig_public_key)
		self.assertEqual(False, request.is_error)

	def test_can_create_request_multisig(self):
		# Act:
		request = OptinRequest(Address(NEM_ADDRESS), HEIGHT, Hash256(HASH_2), Hash256(HASH_1), {
			'type': 101, 'destination': PUBLIC_KEY_1, 'origin': PUBLIC_KEY_2
		})

		# Assert:
		self.assertEqual(Address(NEM_ADDRESS), request.address)
		self.assertEqual(HEIGHT, request.optin_transaction_height)
		self.assertEqual(Hash256(HASH_2), request.optin_transaction_hash)
		self.assertEqual(Hash256(HASH_1), request.payout_transaction_hash)
		self.assertEqual(PublicKey(PUBLIC_KEY_1), request.destination_public_key)
		self.assertEqual(PublicKey(PUBLIC_KEY_2), request.multisig_public_key)
		self.assertEqual(False, request.is_error)

	def test_can_create_request_error(self):
		# Act:
		error = OptinRequestError(Address(NEM_ADDRESS), HEIGHT, Hash256(HASH_1), 'this is an error message')

		# Assert:
		self.assertEqual(Address(NEM_ADDRESS), error.address)
		self.assertEqual(HEIGHT, error.optin_transaction_height)
		self.assertEqual(Hash256(HASH_1), error.optin_transaction_hash)
		self.assertEqual('this is an error message', error.message)
		self.assertEqual(True, error.is_error)
