'''
title           : blockchain.py
description     : A blockchain implemenation with group adress structure
author          : Saeed Toosisaeedi
version         : 1
usage           : python blockchain.py
                  python blockchain.py -p 5000
                  python blockchain.py --port 5000
python_version  : 3.6.1
Comments        : The blockchain implementation is mostly based on [1]. 
                  I made a few modifications to the original code in order to add short group signature to the transactions 
                  based on [2], changed the wallet, and added group adrees structure on this blockchain dashbord
References      : [1] http://adilmoujahid.com/posts/2018/03/intro-blockchain-bitcoin-python/
                  [2] https://crypto.stanford.edu/~dabo/pubs/papers/groupsigs.pdf
'''

from collections import OrderedDict

import binascii

import Crypto
import Crypto.Random
from Crypto.Hash import SHA, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

from flask import Flask, jsonify, request, render_template, abort

import json

from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.PKSig import PKSig
from charm.core.engine.util import objectToBytes, bytesToObject
from pg import ShortSig





class Transaction:

    def __init__(self, sender_address, sender_private_key, sender_public_key, recipient_address, value):
        self.sender_address = sender_address
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.recipient_address = recipient_address
        self.value = value

    def __getattr__(self, attr):
        return self.data[attr]

    def to_dict(self):
        return OrderedDict({'sender_address': self.sender_address,
                            'sender_public_key': self.sender_public_key,
                            'recipient_address': self.recipient_address,
                            'value': self.value})

    def sign_transaction(self):
        """
        Sign transaction with private key
        """
        private_key = RSA.importKey(binascii.unhexlify(self.sender_private_key))
        signer = PKCS1_v1_5.new(private_key)
        h = SHA.new(str(self.to_dict()).encode('utf8'))
        return binascii.hexlify(signer.sign(h)).decode('ascii')


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('./index.html')


@app.route('/make/transaction')
def make_transaction():
    return render_template('./make_transaction.html')


@app.route('/view/transactions')
def view_transaction():
    return render_template('./view_transactions.html')


@app.route('/make/group')
def make_group():
    return render_template('./make_group.html')


@app.route('/make/slave')
def make_slave():
    return render_template('./make_slave.html')


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    random_gen = Crypto.Random.new().read
    private_key = RSA.generate(1024, random_gen)
    public_key = private_key.publickey()

    # group = PairingGroup('MNT224')
    # n = 3  # how manu users are in the group
    # user = 1  # which user's key we will sign a message with
    # shortSig = ShortSig(group)
    # (global_public_key, global_master_secret_key, user_secret_keys) = shortSig.keygen(n)
    # private_key = user_secret_keys
    # public_key = global_public_key

    user_address = SHA256.new(data=str(public_key).encode('utf-8')).hexdigest()


    response = {
        'private_key': binascii.hexlify(private_key.exportKey(format='DER')).decode('ascii'),
        'public_key': binascii.hexlify(public_key.exportKey(format='DER')).decode('ascii'),
        'user_address': user_address
    }

    return jsonify(response), 200


@app.route('/generate/transaction', methods=['POST'])
def generate_transaction():
    sender_address = request.form['sender_address']
    sender_public_key = request.form['sender_public_key']
    sender_private_key = request.form['sender_private_key']
    recipient_address = request.form['recipient_address']
    value = request.form['amount']

    try:
        group = PairingGroup('MNT224')
        shortSig = ShortSig(group)

        sender_global_public_key = sender_public_key
        sender_public_key = sender_public_key.encode()
        sender_public_key = bytesToObject(sender_public_key, group)
        print('\n\nsender_public_key : ', sender_public_key)

        sender_private_key = sender_private_key.encode()
        sender_private_key = bytesToObject(sender_private_key, group)
        print('\n\nsender_private_key : ', sender_private_key)

        global_public_key = sender_public_key
        user_secret_key = sender_private_key
        # msg = {
        #     "sender_address": sender_address,
        #     "sender_public_key": str(sender_public_key),
        #     "recipient_address": recipient_address,
        #     "value": value
        # }
        transaction = OrderedDict({'sender_address': sender_address,
                                    'sender_public_key': sender_global_public_key,
                                    'recipient_address': recipient_address,
                                    'value': value})
        transaction = json.dumps(transaction)
        transaction = SHA256.new(data=str(transaction).encode('utf-8')).hexdigest()
        print("\n\nmsg", transaction)

        signature = shortSig.sign(global_public_key, user_secret_key, transaction)
        signature_bytes = objectToBytes(signature, group)
        signature_str = signature_bytes.decode()

        print('\n\nsignature : ', signature)

    except:
        # sender_global_public_key = sender_public_key
        transaction = Transaction(sender_address, sender_private_key, sender_global_public_key, recipient_address, value)
        signature_str = transaction.sign_transaction()
        print('\n\ntransaction : ', transaction)
        print('\n\ntransaction.to_dict() : ', transaction.to_dict())
        print('\n\ntransaction.sign_transaction() : ', transaction.sign_transaction())



    transaction = OrderedDict({'sender_address': sender_address,
                                'sender_global_public_key': sender_global_public_key, 
                                'recipient_address': recipient_address, 
                                'value': value})
    print('\n\ntransaction : ', transaction)

    response = {'transaction': transaction, 'signature': signature_str}

    return jsonify(response), 200


@app.route('/generate/group', methods=['POST'])
def generate_group():

    last_group = 0
    file_address = './database/group_counter.txt'
    try:
        file = open(file_address, 'r')
        last_group = int(file.read())
    except IOError:
        pass
    finally:
        file = open(file_address, 'w')
        file.write(str(last_group+1))
        file.close()

    group = PairingGroup('MNT224')
    number_of_slaves = int(request.form['number_of_slaves'])
    shortSig = ShortSig(group)
    (global_public_key, global_master_secret_key, user_secret_keys) = shortSig.keygen(number_of_slaves)
    print('\n\nglobal_public_key : ', global_public_key)
    print('\n\nuser_secret_keys : ', user_secret_keys)

    # user_secret_keys_json = json.dumps(user_secret_keys)
    group_address = SHA256.new(data=str(global_public_key).encode('utf-8')).hexdigest()

    global_public_key_bytes = objectToBytes(global_public_key, group)
    global_public_key_str = global_public_key_bytes.decode()
    global_master_secret_key_bytes = objectToBytes(global_master_secret_key, group)
    global_master_secret_key_str = global_master_secret_key_bytes.decode()
    user_secret_keys_str = dict()
    for i in user_secret_keys:
        user_secret_key_bytes = objectToBytes(user_secret_keys[i], group)
        user_secret_key_str = user_secret_key_bytes.decode()
        user_secret_keys_str[str(i)] = user_secret_key_str
    user_secret_keys_str = json.dumps(user_secret_keys_str)




    group_dict = {
        "global_public_key": global_public_key_str,
        "global_master_secret_key": global_master_secret_key_str,
        "group_address": str(group_address),
        "group_id": last_group,
        "last_slave": 0,
        "number_of_slaves": number_of_slaves,
        "user_secret_keys": user_secret_keys_str
    }

    file_group_address = './database/' + str(last_group)
    with open(file_group_address, 'w') as f:
        group_json = json.dumps(group_dict) 
        f.write(str(group_json))

        response = {
            "global_public_key": str(global_public_key),
            "global_master_secret_key": str(global_master_secret_key),
            "group_address": str(group_address),
            "group_id": last_group
        }    
    return jsonify(group_dict), 200


@app.route('/generate/slave', methods=['POST'])
def generate_slave():

    group_id = int(request.form['group_id'])
    print('\n\ngroup_id', group_id)
    file_address = './database/' + str(group_id)
    try:
        file = open(file_address, 'r')
        group_dict = json.load(file)
    except IOError:
        abort(404)

    if group_dict['last_slave'] >= group_dict['number_of_slaves']:
        abort(404)

    last_slave = group_dict['last_slave']
    user_secret_keys = group_dict['user_secret_keys']
    user_secret_keys = json.loads(user_secret_keys) 
    user_secret_key = user_secret_keys[str(last_slave)]

    last_slave = last_slave + 1
    group_dict['last_slave'] = last_slave

    file_group_address = './database/' + str(group_dict['group_id'])
    with open(file_group_address, 'w') as f:
        group_json = json.dumps(group_dict) 
        f.write(str(group_json))

    response = {
        "global_public_key": group_dict['global_public_key'],
        "group_address": group_dict['group_address'],
        "user_secret_key": str(user_secret_key)
    }

    return jsonify(response), 200




if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='127.0.0.1', port=port)
