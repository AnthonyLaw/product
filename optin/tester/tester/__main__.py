#!/usr/bin/env python

import asyncio
import json
from binascii import hexlify, unhexlify
from collections import namedtuple

from symbolchain.Bip32 import Bip32
from symbolchain.CryptoTypes import PrivateKey, PublicKey
from symbolchain.facade.SymbolFacade import SymbolFacade
from symbolchain.facade.NemFacade import NemFacade
from symbolchain.nc import Amount

from client.NemClient import NemClient


NemAccount = namedtuple('NemAccount', ['key_pair', 'address'])

def to_hex_string(buffer):
	return hexlify(buffer.encode('utf8')).decode('utf8')


def derive_key(root_node, facade, change, index):
	path = [44, facade.BIP32_COIN_ID, 0, change, index]

	child_node = root_node.derive_path(path)
	child_key_pair = facade.bip32_node_to_key_pair(child_node)
	address = facade.network.public_key_to_address(child_key_pair.public_key)

	return (path, child_key_pair, address)


def prepare_nem_multisig_transaction(nem_facade, key_pair, nem_network_time, min_approval_delta, cosignatory_public_keys):
	def public_key_to_modification(public_key):
		return {'modification': {'modification_type': 'add_cosignatory', 'cosignatory_public_key': public_key}}

	def monkey_patch(modifications):
		modifications.sort(key=lambda e: nem_facade.network.public_key_to_address(e['modification']['cosignatory_public_key']))
		return modifications

	transaction = nem_facade.transaction_factory.create({
		'type': 'multisig_account_modification_transaction',
		'signer_public_key': key_pair.public_key,
		'timestamp': nem_network_time.timestamp,
		'deadline': nem_network_time.add_hours(1).timestamp,
		'fee': 500000,
		'min_approval_delta': min_approval_delta,
		'modifications': monkey_patch(list(map(public_key_to_modification, cosignatory_public_keys)))
	})
	signature = nem_facade.sign_transaction(key_pair, transaction)
	payload = nem_facade.transaction_factory.attach_signature(transaction, signature)
	return json.loads(payload)


async def prepare_and_announce_nem_multisig(nem_facade, nem_client, nem_network_time, nem_accounts, multisig_id, cosigatory_ids, min_approval_delta):
	key_pair = nem_accounts[multisig_id].key_pair
	multisig_address = nem_facade.network.public_key_to_address(key_pair.public_key)
	result = await nem_client.account(multisig_address)

	# already multisig
	if result['meta']['cosignatories']:
		print(f'{multisig_address} is already a multisig, skipping setup')
		return

	print(f'setting up {multisig_address} as multisig')
	print(result)
	print('....')

	cosignatory_public_keys = list(map(lambda key_id: nem_accounts[key_id].key_pair.public_key, cosigatory_ids))
	request = prepare_nem_multisig_transaction(nem_facade, key_pair, nem_network_time, min_approval_delta, cosignatory_public_keys)
	result = await nem_client.announce(request)
	print(result)


def prepare_nem_transfer_transaction(nem_facade, key_pair, nem_network_time, reicipient_address, message_text):
	transaction = nem_facade.transaction_factory.create({
		'type': 'transfer_transaction',
		'signer_public_key': key_pair.public_key,
		'timestamp': nem_network_time.timestamp,
		'deadline': nem_network_time.add_hours(1).timestamp,
		'fee': 0,
		'recipient_address': str(reicipient_address),
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
	return json.loads(payload)


async def main():
	# read nem accounts
	with open('resources/nem-accounts.txt', 'r') as input_file:
		accounts = list(map(lambda s: s.split(), input_file.readlines()))

	# generate symbol accounts
	symbol_facade = SymbolFacade('testnet')
	bip = Bip32(symbol_facade.BIP32_CURVE_NAME)
	root_node = bip.from_mnemonic('axis buzz cycle dynamic eyebrow future gym hybrid ivory just know lyrics', 'correcthorsebatterystaple')
	symbol_accounts = [derive_key(root_node, symbol_facade, change, 0) for change in range(20, 20+15)]

	# verify addresses
	nem_facade = NemFacade('testnet')
	optin_destination_account = nem_facade.network.public_key_to_address(PublicKey(to_hex_string('testnet optin destination #00002')))
	nem_accounts = []
	for entry in accounts:
		key_pair = nem_facade.KeyPair(PrivateKey(unhexlify(entry[1])))
		nem_address = nem_facade.network.public_key_to_address(key_pair.public_key)
		nem_accounts.append(NemAccount(key_pair, nem_address))
		assert entry[0] == str(nem_address)


	print(f'destination {optin_destination_account}')

	# time
	nem_client = NemClient('http://hugetestalice2.nem.ninja:7890')
	nem_network_time = await nem_client.node_time()

	# accounts layout (0-based)
	# 1-6 single
	#
	# 13 - multisig v2 2-of-3, cosigs: 7, 8, 9
	# 14 - multisig v2 3-of-3, cosigs: 10, 11, 12

	await prepare_and_announce_nem_multisig(nem_facade, nem_client, nem_network_time, nem_accounts, 14, [10, 11, 12], 3)
	await prepare_and_announce_nem_multisig(nem_facade, nem_client, nem_network_time, nem_accounts, 13, [7, 8, 9], 2)

	# create transactions
	for index, nem_account in enumerate(nem_accounts[:6]):
		message_text = json.dumps({'type': 100, 'destination': str(symbol_accounts[index][1].public_key)})

		request = prepare_nem_transfer_transaction(nem_facade, nem_account.key_pair, nem_network_time, optin_destination_account, message_text)
		print(request)
		result = await nem_client.announce(request)
		print(result)
		await asyncio.sleep(0.5)

	print('---')
	print('OPTING in 13')

	# optin account 13:
	for index, nem_account in enumerate(nem_accounts[7:9]):
		message_text = json.dumps({
			'type': 101,
			'origin': str(nem_accounts[13].key_pair.public_key),
			'destination': str(symbol_accounts[13][1].public_key)
		})
		request = prepare_nem_transfer_transaction(nem_facade, nem_account.key_pair, nem_network_time, optin_destination_account, message_text)
		print(request)
		result = await nem_client.announce(request)
		print(result)
		await asyncio.sleep(0.5)

	print('---')
	print('OPTING in 14')

	# optin account 14:
	for index, nem_account in enumerate(nem_accounts[10:13]):
		message_text = json.dumps({
			'type': 101,
			'origin': str(nem_accounts[14].key_pair.public_key),
			'destination': str(symbol_accounts[14][1].public_key)
		})
		request = prepare_nem_transfer_transaction(nem_facade, nem_account.key_pair, nem_network_time, optin_destination_account, message_text)
		print(request)
		result = await nem_client.announce(request)
		print(result)
		await asyncio.sleep(0.5)

if '__main__' == __name__:
	asyncio.run(main())
