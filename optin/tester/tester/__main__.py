#!/usr/bin/env python

import asyncio
import json
from binascii import hexlify, unhexlify

from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.nc import Amount

from client.NemClient import NemClient

def to_hex_string(buffer):
	return hexlify(buffer.encode('utf8')).decode('utf8')


def derive_key(root_node, facade, change, index):
	path = [44, facade.BIP32_COIN_ID, 0, change, index]

	child_node = root_node.derive_path(path)
	child_key_pair = facade.bip32_node_to_key_pair(child_node)
	address = facade.network.public_key_to_address(child_key_pair.public_key)

	return (path, child_key_pair, address)


async def prepare_multisig(nem_facade, nem_client, nem_network_time, nem_kp, multisig_id, cosigatory_ids, min_approval_delta):
	key_pair = nem_kp(multisig_id)
	multisig_address = nem_facade.network.public_key_to_address(key_pair.public_key)
	result = await nem_client.account(multisig_address)
	print(multisig_address)
	print(result)
	print('....')

	def id_to_modification(key_id):
		return {'modification': {'modification_type': 'add_cosignatory', 'cosignatory_public_key': nem_kp(key_id).public_key}}

	# already multisig
	if result['meta']['cosignatories']:
		return

	transaction = nem_facade.transaction_factory.create({
		'type': 'multisig_account_modification_transaction',
		'signer_public_key': key_pair.public_key,
		'timestamp': nem_network_time.timestamp,
		'deadline': nem_network_time.add_hours(1).timestamp,
		'fee': 500000,
		'min_approval_delta': min_approval_delta,
		'modifications': list(map(id_to_modification, cosigatory_ids))
	})
	signature = nem_facade.sign_transaction(key_pair, transaction)
	payload = nem_facade.transaction_factory.attach_signature(transaction, signature)

	print(transaction)

	request = json.loads(payload)
	result = await nem_client.announce(request)
	print(result)


async def prepare_transfer(nem_facade, nem_client, nem_network_time, nem_kp, signer_id):
	key_pair = nem_kp(signer_id)
	signer_address = nem_facade.network.public_key_to_address(key_pair.public_key)
	result = await nem_client.account(signer_address)
	print(signer_address)
	print(result)
	print('....')
	transaction = nem_facade.transaction_factory.create({
		'type': 'transfer_transaction',
		'signer_public_key': key_pair.public_key,
		'timestamp': nem_network_time.timestamp,
		'deadline': nem_network_time.add_hours(1).timestamp,
		'fee': 0,
		'recipient_address': str(signer_address),
		'amount': 0,
		'message_envelope_size': 0
	})
	transaction.fee = Amount(50000 * 25)

	signature = nem_facade.sign_transaction(key_pair, transaction)
	payload = nem_facade.transaction_factory.attach_signature(transaction, signature)

	request = json.loads(payload)
	result = await nem_client.announce(request)
	print(result)


async def main():
	# read nem accounts
	with open('resources/nem-accounts.txt', 'r') as input_file:
		accounts = list(map(lambda s: s.split(), input_file.readlines()))

	# generate symbol accounts
	symbol_facade = SymbolFacade('testnet')
	bip = Bip32(symbol_facade.BIP32_CURVE_NAME)
	root_node = bip.from_mnemonic('axis buzz cycle dynamic eyebrow future gym hybrid ivory just know lyrics', 'correcthorsebatterystaple')
	symbol_accounts = [derive_key(root_node, symbol_facade, change, 0) for change in range(1, 16)]

	# verify addresses
	nem_facade = NemFacade('testnet')
	optin_destination_account = nem_facade.network.public_key_to_address(PublicKey(to_hex_string('testnet optin destination #00002')))
	for entry in accounts:
		key_pair = nem_facade.KeyPair(PrivateKey(unhexlify(entry[1])))
		nem_address = nem_facade.network.public_key_to_address(key_pair.public_key)
		assert entry[0] == str(nem_address)


	print(f'destination {optin_destination_account}')

	# time
	nem_client = NemClient('http://hugetestalice2.nem.ninja:7890')
	nem_network_time = await nem_client.node_time()

	def nem_kp(index):
		return nem_facade.KeyPair(PrivateKey(unhexlify(accounts[index][1])))

	# accounts layout (0-based)
	# 1-6 single
	#
	# 13 - multisig v2 2-of-3, cosigs: 7, 8, 9
	# 14 - multisig v1 3-of-3, cosigs: 10, 11, 12

	# just a test transfer to verify if account #14 private key is correct
	# await prepare_transfer(nem_facade, nem_client, nem_network_time, nem_kp, 14)

	await prepare_multisig(nem_facade, nem_client, nem_network_time, nem_kp, 14, [10, 11, 12], 3)
	print('---')
	await prepare_multisig(nem_facade, nem_client, nem_network_time, nem_kp, 13, [7, 8, 9], 2)

	return

	##
	## Temporarily switched via return above
	##

	# create transactions
	for index, entry in enumerate(accounts):
		key_pair = nem_facade.KeyPair(PrivateKey(unhexlify(entry[1])))

		message_text = json.dumps({'type': 100, 'destination': str(symbol_accounts[index][1].public_key)})

		transaction = nem_facade.transaction_factory.create({
			'type': 'transfer_transaction',
			'signer_public_key': key_pair.public_key,
			'timestamp': nem_network_time.timestamp,
			'deadline': nem_network_time.add_hours(1).timestamp,
			'fee': 0,
			'recipient_address': optin_destination_account,
			'amount': 0,
			'message_envelope_size': 1,
			'message': {
				'message_type': 'plain',
				'message': message_text
			}
		})
		transaction.message_envelope_size = len(message_text) + 8
		transaction.fee = Amount(50000 * (25 + 1 + len(message_text) // 32))

		signature = nem_facade.sign_transaction(key_pair, transaction)
		payload = nem_facade.transaction_factory.attach_signature(transaction, signature)

		request = json.loads(payload)
		result = await nem_client.announce(request)
		print(result)

		await asyncio.sleep(1)


if '__main__' == __name__:
	asyncio.run(main())
