# -*- encoding: utf-8 -*-
# AESCipher
# from core.utils import AESCipher
## Hash lib
import hashlib
import logging
from datetime import timedelta, datetime
import rsa
import cPickle
import binascii
import qrcode
import base64
# Unicode shite
import unicodedata
from django.utils.encoding import python_2_unicode_compatible
# FOr signing
import md5
from Crypto.PublicKey import RSA
from Crypto.Util import asn1
from base64 import b64decode
import merkletools
# PoE
from blockcypher import embed_data, get_transaction_details
from django.conf import settings

# Returns a tuple with Private and Public keys
def get_new_asym_keys():
    return rsa.newkeys(512)

# Give it a key, returns a hex string ready to save
def savify_key(EncryptionPublicKey):
    pickld_key = cPickle.dumps(EncryptionPublicKey)
    return bin2hex(pickld_key)

def calculate_hash(index, previousHash, timestamp, data):
    # Calculate hash
    hash_obj = hashlib.sha256(str(index) + previousHash + str(timestamp) + data)
    return hash_obj.hexdigest()

def create_hash256(data):
    ''' Given a string return it with hash256 '''
    hash_obj = hashlib.sha256(str(data))
    return hash_obj.hexdigest()

# Give it a hex saved string, returns a Key object ready to use
def un_savify_key(HexPickldKey):
    bin_str_key = hex2bin(HexPickldKey)
    return cPickle.loads(bin_str_key)

# Encrypt with PublicKey object
def encrypt_with_public_key(message, EncryptionPublicKey):
    encryptedtext=rsa.encrypt(message, EncryptionPublicKey)
    return encryptedtext

# Decrypt with private key
def decrypt_with_private_key(encryptedtext, EncryptionPrivateKey):
    message =rsa.decrypt(encryptedtext, EncryptionPrivateKey)
    return message

# A simple implementation
def test(message):
    print "This is the original message: "+message
    (EncryptionPublicKey, EncryptionPrivateKey) = get_new_asym_keys()
    # Encrypt with public keys
    encryptedtext = encrypt_with_public_key(message, EncryptionPublicKey)
    print "This is the encrypted message: "+encryptedtext
    # Decrypt with private keys
    decrypted_message = decrypt_with_private_key(encryptedtext, EncryptionPrivateKey)
    print "This is the decrypted message: "+decrypted_message


# convert str to hex
# This needs to be used to save the messages and keys
def bin2hex(binStr):
    return binascii.hexlify(binStr)
# convert hex to str
def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


''' Sign and verify functions '''
def sign(message, PrivateKey):
    signature = rsa.sign(message, PrivateKey, 'SHA-1')
    return base64.b64encode(signature)

def verify_signature(message, signature, PublicKey):
    ''' Convert signature and check message with it '''
    try:
        signature = binascii.unhexlify(signature)
        return rsa.verify(message, signature, PublicKey)
    except Exception as e:
        print("[CryptoTool, verify ERROR ] Signature or message are corrupted: Error: {}, type: {}".format(e, type(e)))
        return False

# Merkle root - gets a list of prescriptions and returns a merkle root
def get_merkle_root(prescriptions):
    # Generate merkle tree
    logger = logging.getLogger('django_info')
    mt = merkletools.MerkleTools() # Default is SHA256
    # Build merkle tree with Rxs
    for rx in prescriptions:
        mt.add_leaf(rx.hash_id)
    mt.make_tree();
    # Just to check
    logger.error("Leaf Count: {}".format(mt.get_leaf_count()))
    # get merkle_root and return
    return mt.get_merkle_root();

#  Proves a hash is in merkle root of block merkle tree
def is_rx_in_block(target_rx, block):
    #  We need to create a new tree and follow the path to get this proof
    logger = logging.getLogger('django_info')
    mtn = merkletools.MerkleTools()
    rx_hashes = block.data["hashes"]
    n = 0
    for index, hash in enumerate(rx_hashes):
        mtn.add_leaf(hash)
        if target_rx.hash_id == hash:
            n = index
    # Make the tree and get the proof
    mtn.make_tree()
    proof = mtn.get_proof(n)
    logger.error("Proof: {}".format(proof))
    return mtn.validate_proof(proof, target_rx.hash_id, block.merkleroot)


def get_qr_code(data, file_path="/tmp/qrcode.jpg"):
    ''' Create a QR Code Image and return it '''
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image()
    img.save(file_path)
    with open(file_path, "rb") as f:
        return f.read()

class PoE(object):
    ''' Object tools for encrypt and decrypt info '''
    logger = logging.getLogger('django_info')

    def journal(self, merkle_root):
        try:
            data = embed_data(to_embed=merkle_root, api_key=settings.BLOCKCYPHER_API_TOKEN, coin_symbol=settings.CHAIN)
            if isinstance(data, dict):
                self.logger.info('[PoE data]:{}'.format(data))
                return data.get("hash", "")
            else:
                self.logger.error("Type of data:".format(type(data)))
                return None
        except Exception as e:
            self.logger.error("[PoE ERROR] Error returning hash from embed data, Error :{}, type({})".format(e, type(e)))

    def attest(self, txid):
        try:
            return get_transaction_details(txid, coin_symbol=settings.CHAIN)
        except Exception as e:
            print("[PoE ERROR] Error returning transantion details :%s, type(%s)" % (e, type(e)))
            raise e

def privkey_string_to_rsa(string_key):
    '''Take a private key created with jsencrypt and convert it into
    a rsa data of python'''
    with open('privkey.pem','wb') as file:
        file.write(string_key)

    with open('privkey.pem','rb') as file:
        priv_key = file.read()

    privkey = rsa.PrivateKey.load_pkcs1(priv_key)
    #data is rsa type
    return privkey

def pubkey_string_to_rsa(string_key):
    '''Take a public key created with jsencrypt and convert it into
    a rsa data of python'''
    with open('pubkey.pem','wb') as file:
        file.write(string_key)

    with open('pubkey.pem','rb') as file:
        pub_key = file.read()

    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub_key)
    #data is rsa type
    return pubkey


def pubkey_base64_to_rsa(base64_key):
    ''' Convert base64 pub key to pem file and then pub key rsa object '''

    LINE_SIZE = 64
    BEGIN_LINE = "-----BEGIN PUBLIC KEY-----"
    END_LINE = "-----END PUBLIC KEY-----"

    # Replace spaces with plus string, who is remove it when django gets from uri param
    base64_key.replace(" ", "+")

    lines = [base64_key[i:i+LINE_SIZE] for i in range(0, len(base64_key), LINE_SIZE)]

    raw_key = "{}\n".format(BEGIN_LINE)
    for line in lines:
        # iter lines and create s unique string with \n
        raw_key += "{}\n".format(line)

    raw_key += "{}".format(END_LINE)

    return pubkey_string_to_rsa(raw_key), raw_key
