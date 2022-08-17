#!/usr/bin/env python
# -*- coding: utf-8 -*-
import hmac, struct, time, sys, os, codecs, binascii, ecdsa, hashlib, random, ctypes
from time import sleep
import secp256k1 as ice # download from https://github.com/iceland2k14/secp256k1
import threading
from threading import Thread
try:
    from telebot import *
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import requests
    import base58
    from rich import print
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    from lxml import html
    
    
except ImportError:
    import subprocess
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bit']) # https://pypi.org/project/bit/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'requests']) # https://pypi.org/project/requests/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'rich']) # https://pypi.org/project/rich/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'base58']) # https://pypi.org/project/base58/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'simplebloomfilter']) # https://pypi.org/project/simplebloomfilter/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'bitarray==1.9.2'])
    subprocess.check_call(["python", '-m', 'pip', 'install', 'lxml']) # https://pypi.org/project/lxml/
    subprocess.check_call(["python", '-m', 'pip', 'install', 'pyTelegramBotAPI']) # https://pypi.org/project/pyTelegramBotAPI/
    from telebot import *
    import bit
    from bit import Key
    from bit.format import bytes_to_wif
    import requests
    import base58
    from rich import print
    from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
    from lxml import html

ctypes.windll.kernel32.SetConsoleTitleW('Mizogg Corp.Telegram Tools')

# =============================================================================
bot = telebot.TeleBot("YOURAPIKEY") # YOUR TELEGRAM API KEY
# =============================================================================
print('[yellow] Please with Database Loading.....[/yellow]')

with open("btc.bf", "rb") as fp:
    bloom_filter = BloomFilter.load(fp)
btc_count = len(bloom_filter)    
print('[yellow] Bitcoin Addresses Loaded  >> [ [/yellow]', btc_count, '[yellow]][/yellow]')
    
with open("eth.bf", "rb") as fp:
    bloom_filter1 = BloomFilter.load(fp)   
eth_count = len(bloom_filter1)
print('[yellow] ETH Addresses Loaded  >> [ [/yellow]', eth_count, '[yellow]][/yellow]')

addr_count = len(bloom_filter)+len(bloom_filter1)
print('[yellow] Total Bitcoin and ETH Addresses Loaded  >> [ [/yellow]', addr_count, '[yellow]][/yellow]')
print('[purple] <<  Telegram Bot Running  >> [/purple]')
# =============================================================================

n = "\n"
order	= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
mylist = []
maxN = 115792089237316195423570985008687907852837564279074904382605163141518161494336
ammount = '0 BTC'
with open('words.txt', newline='', encoding='utf-8') as f:
    for line in f:
        mylist.append(line.strip())

with open('english.txt') as f:
    wordlist = f.read().split('\n')

# =============================================================================

ICEWORDS = '''[red]
 ▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄     ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   ▄▄▄▄▄▄  ▄▄▄▄▄▄▄ 
█   █       █       █  █ █ ▄ █ █       █   ▄  █ █      ██       █
█   █       █    ▄▄▄█  █ ██ ██ █   ▄   █  █ █ █ █  ▄    █  ▄▄▄▄▄█
█   █     ▄▄█   █▄▄▄   █       █  █ █  █   █▄▄█▄█ █ █   █ █▄▄▄▄▄ 
█   █    █  █    ▄▄▄█  █       █  █▄█  █    ▄▄  █ █▄█   █▄▄▄▄▄  █
█   █    █▄▄█   █▄▄▄   █   ▄   █       █   █  █ █       █▄▄▄▄▄█ █
█▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█  █▄▄█ █▄▄█▄▄▄▄▄▄▄█▄▄▄█  █▄█▄▄▄▄▄▄██▄▄▄▄▄▄▄█


                      ___            ___  
                     (o o)          (o o) 
                    (  V  ) MIZOGG (  V  )
                    --m-m------------m-m--
[/red]'''

RANGER = '''[red]
 ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄   
█   ▄  █ █       █  █  █ █       █       █   ▄  █  
█  █ █ █ █   ▄   █   █▄█ █   ▄▄▄▄█    ▄▄▄█  █ █ █  
█   █▄▄█▄█  █▄█  █       █  █  ▄▄█   █▄▄▄█   █▄▄█▄ 
█    ▄▄  █       █  ▄    █  █ █  █    ▄▄▄█    ▄▄  █
█   █  █ █   ▄   █ █ █   █  █▄▄█ █   █▄▄▄█   █  █ █
█▄▄▄█  █▄█▄▄█ █▄▄█▄█  █▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄█  █▄█



                  ___            ___  
                 (o o)          (o o) 
                (  V  ) MIZOGG (  V  )
                --m-m------------m-m--
[/red]'''

FULLRANGE = '''[red]
 ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄     ▄▄▄        ▄▄▄▄▄▄   ▄▄▄▄▄▄▄ ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ 
█       █  █ █  █   █   █   █      █   ▄  █ █       █  █  █ █       █       █
█    ▄▄▄█  █ █  █   █   █   █      █  █ █ █ █   ▄   █   █▄█ █   ▄▄▄▄█    ▄▄▄█
█   █▄▄▄█  █▄█  █   █   █   █      █   █▄▄█▄█  █▄█  █       █  █  ▄▄█   █▄▄▄ 
█    ▄▄▄█       █   █▄▄▄█   █▄▄▄   █    ▄▄  █       █  ▄    █  █ █  █    ▄▄▄█
█   █   █       █       █       █  █   █  █ █   ▄   █ █ █   █  █▄▄█ █   █▄▄▄ 
█▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█  █▄▄▄█  █▄█▄▄█ █▄▄█▄█  █▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█




                          ___            ___  
                         (o o)          (o o) 
                        (  V  ) MIZOGG (  V  )
                        --m-m------------m-m--
[/red]'''
# =============================================================================
def create_valid_mnemonics(strength=128):

    rbytes = os.urandom(strength // 8)
    h = hashlib.sha256(rbytes).hexdigest()
    
    b = ( bin(int.from_bytes(rbytes, byteorder="big"))[2:].zfill(len(rbytes) * 8) \
         + bin(int(h, 16))[2:].zfill(256)[: len(rbytes) * 8 // 32] )
    
    result = []
    for i in range(len(b) // 11):
        idx = int(b[i * 11 : (i + 1) * 11], 2)
        result.append(wordlist[idx])

    return " ".join(result)

def mnem_to_seed(words):
    salt = 'mnemonic'
    seed = hashlib.pbkdf2_hmac("sha512",words.encode("utf-8"), salt.encode("utf-8"), 2048)
    return seed


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code

def parse_derivation_path(str_derivation_path="m/44'/0'/0'/0/0"):      # 60' is for ETH 0' is for BTC
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/44'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def parse_derivation_path2(str_derivation_path="m/49'/0'/0'/0/0"):      
    path = []
    if str_derivation_path[0:2] != 'm/':
        raise ValueError("Can't recognize derivation path. It should look like \"m/49'/0'/0'/0\".")
    for i in str_derivation_path.lstrip('m/').split('/'):
        if "'" in i:
            path.append(0x80000000 + int(i[:-1]))
        else:
            path.append(int(i))
    return path

def derive_bip32childkey(parent_key, parent_chain_code, i):
    assert len(parent_key) == 32
    assert len(parent_chain_code) == 32
    k = parent_chain_code
    if (i & 0x80000000) != 0:
        key = b'\x00' + parent_key
    else:
#        key = bytes(PublicKey(parent_key))
        key = bit.Key.from_bytes(parent_key).public_key
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % order
        if a < order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code
    
def bip39seed_to_private_key(bip39seed, n=1):
    const = "m/44'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/0'/0'/0/0"
    derivation_path = parse_derivation_path(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
    
def bip39seed_to_private_key2(bip39seed, n=1):
    const = "m/49'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/49'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key3(bip39seed, n=1):
    const = "m/84'/0'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/84'/0'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key

def bip39seed_to_private_key4(bip39seed, n=1):
    const = "m/44'/60'/0'/0/"
#    str_derivation_path = const + str(n-1)
    str_derivation_path = "m/44'/60'/0'/0/0"
    derivation_path = parse_derivation_path2(str_derivation_path)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key
# =============================================================================
def get_balance(caddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + caddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code = html.fromstring(byte_string)
    return source_code
    
def get_balance1(uaddr):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + uaddr
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code1 = html.fromstring(byte_string)
    return source_code1

def get_balance2(p2sh):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + p2sh
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code2 = html.fromstring(byte_string)
    return source_code2

def get_balance3(bech32):
    urlblock = "https://bitcoin.atomicwallet.io/address/" + bech32
    respone_block = requests.get(urlblock)
    byte_string = respone_block.content
    source_code3 = html.fromstring(byte_string)
    return source_code3

# =============================================================================
class BrainWallet:

    @staticmethod
    def generate_address_from_passphrase(passphrase):
        private_key = str(hashlib.sha256(
            passphrase.encode('utf-8')).hexdigest())
        address =  BrainWallet.generate_address_from_private_key(private_key)
        return private_key, address

    @staticmethod
    def generate_address_from_private_key(private_key):
        public_key = BrainWallet.__private_to_public(private_key)
        address = BrainWallet.__public_to_address(public_key)
        return address

    @staticmethod
    def __private_to_public(private_key):
        private_key_bytes = codecs.decode(private_key, 'hex')
        # Get ECDSA public key
        key = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
        key_bytes = key.to_string()
        key_hex = codecs.encode(key_bytes, 'hex')
        # Add bitcoin byte
        bitcoin_byte = b'04'
        public_key = bitcoin_byte + key_hex
        return public_key

    @staticmethod
    def __public_to_address(public_key):
        public_key_bytes = codecs.decode(public_key, 'hex')
        # Run SHA256 for the public key
        sha256_bpk = hashlib.sha256(public_key_bytes)
        sha256_bpk_digest = sha256_bpk.digest()
        # Run ripemd160 for the SHA256
        ripemd160_bpk = hashlib.new('ripemd160')
        ripemd160_bpk.update(sha256_bpk_digest)
        ripemd160_bpk_digest = ripemd160_bpk.digest()
        ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')
        # Add network byte
        network_byte = b'00'
        network_bitcoin_public_key = network_byte + ripemd160_bpk_hex
        network_bitcoin_public_key_bytes = codecs.decode(
            network_bitcoin_public_key, 'hex')
        # Double SHA256 to get checksum
        sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
        sha256_nbpk_digest = sha256_nbpk.digest()
        sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
        sha256_2_nbpk_digest = sha256_2_nbpk.digest()
        sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
        checksum = sha256_2_hex[:8]
        # Concatenate public key and checksum to get the address
        address_hex = (network_bitcoin_public_key + checksum).decode('utf-8')
        wallet = BrainWallet.base58(address_hex)
        return wallet

    @staticmethod
    def base58(address_hex):
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        b58_string = ''
        # Get the number of leading zeros and convert hex to decimal
        leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
        # Convert hex to decimal
        address_int = int(address_hex, 16)
        # Append digits to the start of string
        while address_int > 0:
            digit = address_int % 58
            digit_char = alphabet[digit]
            b58_string = digit_char + b58_string
            address_int //= 58
        # Add '1' for each 2 leading zeros
        ones = leading_zeros // 2
        for one in range(ones):
            b58_string = '1' + b58_string
        return b58_string
# =============================================================================
@bot.message_handler(commands=["start"])
def start(message):
    print('[green]starting..........[/green]')
    markup_start = types.ReplyKeyboardMarkup(resize_keyboard=True)
    option1 = types.KeyboardButton("🪓Address with Balance Check🪓")
    option2 = types.KeyboardButton("🔨HEX to Address with Balance Check🔨")
    option3 = types.KeyboardButton("⛏️DEC to Address with Balance Check⛏️")
    option4 = types.KeyboardButton("🔥WIF to Address with Balance Check🔥")
    option5 = types.KeyboardButton("🧠BrainWallet to Address with Balance Check🧠")
    option6 = types.KeyboardButton("✍️Mnenomic to Address with Balance Check✍️")
    option7 = types.KeyboardButton("🔋Power Hour Words 🔋✨(Pro Access)✨")
    option8 = types.KeyboardButton("🔋Power Hour Range 🔋✨(Pro Access)✨")
    option9 = types.KeyboardButton("✨Range Selector ✨(Pro Access)✨")
    option10 = types.KeyboardButton("ℹ️HELP and Information🦮")
    markup_start.add(option1, option2, option3, option4, option5, option6, option7, option8, option9, option10)
    bot.send_message(message.chat.id, f"🤖 Hello , {message.from_user.first_name}! Welcome to Mizogg's Crypto Tools Please Pick an Option to get Started 🪓🔨⛏️", reply_markup=markup_start)

@bot.message_handler(content_types=["text"])
def get_text(message):
    if message.text=="🪓Address with Balance Check🪓":
        print('[green]starting Crypto Balance Check Tool..........[/green]')
        markup_crypto = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("🪙BTC Address with Balance Check🪙")
        option2 = types.KeyboardButton("🪙ETC Address with Balance Check COMING SOON🪙")
        back = types.KeyboardButton("🔙Back")
        markup_crypto.add(option1, back)
        bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! Please pick ₿itcoin & Ethereum Balance Checker Button 🪓🔨⛏️", reply_markup=markup_crypto)
    
    if message.text=="🔙Back":
        start(message)
        
    if message.text=="ℹ️HELP and Information🦮":
        bot.send_message(message.chat.id, f" ⛔️⚠️ATTENTION ALL, To avoid problems, this @Mizoggs_Crypto_Tools_Bot bot is in TEST mode, we check it for errors, speed and everything else, do not use your personal addresses, passwords and everything else, in order to avoid problems, all positive information comes to the author he sees everything, I think everyone understood!!! Please check out Main Crypto Crackers https://t.me/CryptoCrackersUK ⛔️⚠️ DO NOT USE YOUR OWN PRIVATE KEYS⚠️⛔️")
        time.sleep(2.5)
        start(message) 
    
    if message.text=="🪙BTC Address with Balance Check🪙":
        print('[red]Bitcoin Address Balance Info Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
        back = types.KeyboardButton("🔙Back")
        markup_back.add(back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! Please Enter ₿itcoin Address to Check ", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_address)
        
    if message.text=="🔨HEX to Address with Balance Check🔨":
        print('[red]HEX to Address Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
        back = types.KeyboardButton("🔙Back")
        markup_back.add(back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🔨HEX to Address with Balance Check Please Enter a Hexadecimal Private Key to Begin (Hexadecimal (or hex) is a base 16 system used to simplify how binary is represented. A hex digit can be any of the following 16 digits: 0 1 2 3 4 5 6 7 8 9 A B C D E F.)", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_HEX)
        
    if message.text=="⛏️DEC to Address with Balance Check⛏️":
        print('[red]DEC to Address Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
        back = types.KeyboardButton("🔙Back")
        markup_back.add(back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! ⛏️DEC to Address with Balance Check Please Enter a Decimal Private Key to Begin. Decimal System lets us write numbers as large or as small as we want within the 256Bit Range ", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_DEC)
    
    if message.text=="🔥WIF to Address with Balance Check🔥":
        print('[red]WIF to Address Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
        back = types.KeyboardButton("🔙Back")
        markup_back.add(back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🔥WIF to ₿itcoin Address with Balance Check", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_WIF)
     
    if message.text=="🧠BrainWallet to Address with Balance Check🧠":
        markup_brain = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("🧠Enter Your Own Brain Wallet🧠")
        option2 = types.KeyboardButton("🧠Random Ammount of Brain Words with Balance Check🧠")
        back = types.KeyboardButton("🔙Back")
        markup_brain.add(option1, option2, back)
        bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! PICK Enter Your Own Brain words or Random Ammount Generator Checker Button 🪓🔨⛏️", reply_markup=markup_brain)

    if message.text=="🧠Enter Your Own Brain Wallet🧠":
        print('[red]BrainWallet to Address Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=1)
        back = types.KeyboardButton("🔙Back")
        markup_back.add(back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🧠BrainWallet to ₿itcoin Address with Balance Check", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_BRAIN)

    if message.text=="🧠Random Ammount of Brain Words with Balance Check🧠":
        print('[red]Random BrainWallet to Address Check Tool Entered [/red]')
        markup_brain = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("1-3 Words")
        option2 = types.KeyboardButton("3-6 Words")
        option3 = types.KeyboardButton("6-9 Words")
        option4 = types.KeyboardButton("9-12 Words")
        option5 = types.KeyboardButton("12-15 Words")
        option6 = types.KeyboardButton("15-18 Words")
        option7 = types.KeyboardButton("18-21 Words")
        option8 = types.KeyboardButton("21-24 Words")
        option9 = types.KeyboardButton("24-50 Words")
        markup_brain.add(option1, option2, option3, option4, option5, option6, option7, option8, option9)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🧠 Random BrainWallet to ₿itcoin Address with Balance Check", reply_markup=markup_brain)

        bot.register_next_step_handler(send_message, get_BRAIN_RANDOM)

    if message.text=="✍️Mnenomic to Address with Balance Check✍️":
        print('[red]12/24words to Address Check Tool Entered [/red]')
        markup_back = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("✨12 Word ️Mnenomic✨")
        option2 = types.KeyboardButton("✨24 Word ️Mnenomic✨")
        back = types.KeyboardButton("🔙Back")
        markup_back.add(option1, option2, back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! ️Mnenomic to ₿itcoin and Ethereum Address with Balance Check", reply_markup=markup_back)

        bot.register_next_step_handler(send_message, get_WORDS)

    if message.text=="🔋Power Hour Words 🔋✨(Pro Access)✨":
        print('[red]Power Hour Tool Entered [/red]')
        markup_power = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("1 Minutes Magic Random Words")
        option2 = types.KeyboardButton("5 Minutes Magic Random Words")
        option3 = types.KeyboardButton("15 Minutes Magic Random Words ✨(Pro Access)✨")
        option4 = types.KeyboardButton("30 Minutes Magic Random Words ✨(Pro Access)✨")
        option5 = types.KeyboardButton("1 Hour Magic Random Words ✨(Pro Access)✨")
        back = types.KeyboardButton("🔙Back")
        markup_power.add(option1, option2, option3, option4, option5, back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🔋Power Hour Words 🔋✨(Pro Access)✨", reply_markup=markup_power)

        bot.register_next_step_handler(send_message, get_POWER)
        
    if message.text=="🔋Power Hour Range 🔋✨(Pro Access)✨":
        print('[red]Power Hour Tool Entered [/red]')
        markup_POWER_FULLRANGE = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("1 Minutes Magic Random Range")
        option2 = types.KeyboardButton("5 Minutes Magic Random Range")
        option3 = types.KeyboardButton("15 Minutes Magic Random Range ✨(Pro Access)✨")
        option4 = types.KeyboardButton("30 Minutes Magic Random Range ✨(Pro Access)✨")
        option5 = types.KeyboardButton("1 Hour Magic Random Range ✨(Pro Access)✨")
        back = types.KeyboardButton("🔙Back")
        markup_POWER_FULLRANGE.add(option1, option2, option3, option4, option5, back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🔋Power Hour Range 🔋✨(Pro Access)✨", reply_markup=markup_POWER_FULLRANGE)

        bot.register_next_step_handler(send_message, get_POWER_FULLRANGE)

    if message.text=="✨Range Selector ✨(Pro Access)✨":
        print('[red]Range Selector Tool Entered [/red]')
        markup_POWER_RANGE = types.ReplyKeyboardMarkup(resize_keyboard=True)
        option1 = types.KeyboardButton("1-64 Bits")
        option2 = types.KeyboardButton("64-70 Bits")
        option3 = types.KeyboardButton("70-80 Bits")
        option4 = types.KeyboardButton("80-90 Bits")
        option5 = types.KeyboardButton("90-100 Bits")
        option6 = types.KeyboardButton("100-110 Bits")
        option7 = types.KeyboardButton("110-120 Bits")
        option8 = types.KeyboardButton("120-130 Bits")
        option9 = types.KeyboardButton("130-140 Bits")
        option10 = types.KeyboardButton("140-150 Bits")
        option11 = types.KeyboardButton("150-160 Bits")
        option12 = types.KeyboardButton("160-170 Bits")
        option13 = types.KeyboardButton("170-180 Bits")
        option14 = types.KeyboardButton("180-190 Bits")
        option15 = types.KeyboardButton("190-200 Bits")
        option16 = types.KeyboardButton("200-210 Bits")
        option17 = types.KeyboardButton("210-220 Bits")
        option18 = types.KeyboardButton("220-230 Bits")
        option19 = types.KeyboardButton("230-240 Bits")
        option20 = types.KeyboardButton("240-250 Bits")
        option21 = types.KeyboardButton("250-253 Bits")
        option22 = types.KeyboardButton("253-255 Bits")
        option23 = types.KeyboardButton("255-256 Bits")
        back = types.KeyboardButton("🔙Back")
        markup_POWER_RANGE.add(option1, option2, option3, option4, option5, option6, option7, option8, option9, option10, option11, option12, option13, option14, option15, option16, option17, option18, option19, option20, option21, option22, option23, back)

        send_message = bot.send_message(message.chat.id, f"🤖 {message.from_user.first_name}! 🧠✨Range Selector ✨(Pro Access)✨", reply_markup=markup_POWER_RANGE)

        bot.register_next_step_handler(send_message, get_POWER_RANGE)
    if message.text=="Stop":
        global run
        run = False
        bot.send_message(message.chat.id, "The search for wallets has been stopped!")
        start(message)
        
def get_address(message):
    if message.text=="🔙Back":
        start(message)
    else:
        caddr = message.text
        if message.content_type == "text":
            urlblock = "https://bitcoin.atomicwallet.io/address/" + caddr
            respone_block = requests.get(urlblock)
            if respone_block.status_code==200:
                byte_string = respone_block.content
                source_code = html.fromstring(byte_string)
                received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                receivedid = source_code.xpath(received_id)
                totalReceived = str(receivedid[0].text_content())
                sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                sentid = source_code.xpath(sent_id)
                totalSent = str(sentid[0].text_content())
                balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                balanceid = source_code.xpath(balance_id)
                balance = str(balanceid[0].text_content())
                txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                txsid = source_code.xpath(txs_id)
                txs = str(txsid[0].text_content())
                n = "\n"
                bot.send_message(message.chat.id, f"        👇 ₿itcoin Adress Entered 👇{n}{n} {caddr} {n}{n}      💰 Balance 💰 {balance} {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs}")
                print('[purple] Bitcoin Address Entered  >> [ [/purple]', caddr, '[purple]][/purple]')
                print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            else:
                bot.send_message(message.chat.id, "🚫 This ₿itcoin address is not valid 🤪 A BTC address is alphanumeric and always starts with a 1 or a 3 or bc1. This is an example of a receiving address: 1FeexV6bAHb8ybZjqQMjJrcCrHGW9sb6uF . Please note: this is just an example address.")
                print('[red] This Bitcoin address is not valid [/red]')
        else:
            bot.send_message(message.chat.id, "🚫 This ₿itcoin address is not valid 🤪 Send in text format")
        start(message)

def checkHex(HEX):
    for ch in HEX:
        if ((ch < '0' or ch > '9') and (ch < 'a' or ch > 'f') and (ch < 'A' or ch > 'F')):
                 
            print("No")
            return False
    print("Yes")
    return True

def get_HEX(message):
    if message.text=="🔙Back":
        start(message)
    else:
        HEX = message.text
        if message.content_type == "text":
            checkHex(HEX)
            if checkHex(HEX)==True:
                dec = int(HEX, 16)
                if dec < maxN:
                    ammount = '0 BTC'
                    length = len(bin(dec))
                    length -=2
                    print('\nHexadecimal = ',HEX, '\nTo Decimal = ', dec, '  bits ', length)
                    wifc = ice.btc_pvk_to_wif(HEX)
                    wifu = ice.btc_pvk_to_wif(HEX, False)
                    caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                    uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                    p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                    bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                    
                    source_code = get_balance(caddr)
                    received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid = source_code.xpath(received_id)
                    totalReceived = str(receivedid[0].text_content())
                    sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid = source_code.xpath(sent_id)
                    totalSent = str(sentid[0].text_content())
                    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid = source_code.xpath(balance_id)
                    balance = str(balanceid[0].text_content())
                    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid = source_code.xpath(txs_id)
                    txs = str(txsid[0].text_content())

                    source_code1 = get_balance1(uaddr)
                    received_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid1 = source_code1.xpath(received_id1)
                    totalReceived1 = str(receivedid1[0].text_content())
                    sent_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid1 = source_code1.xpath(sent_id1)
                    totalSent1 = str(sentid1[0].text_content())
                    balance_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid1 = source_code1.xpath(balance_id1)
                    balance1 = str(balanceid1[0].text_content())
                    txs_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid1 = source_code1.xpath(txs_id1)
                    txs1 = str(txsid1[0].text_content())

                    source_code2 = get_balance2(p2sh)
                    received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid2 = source_code2.xpath(received_id2)
                    totalReceived2 = str(receivedid2[0].text_content())
                    sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid2 = source_code2.xpath(sent_id2)
                    totalSent2 = str(sentid2[0].text_content())
                    balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid2 = source_code2.xpath(balance_id2)
                    balance2 = str(balanceid2[0].text_content())
                    txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid2 = source_code2.xpath(txs_id2)
                    txs2 = str(txsid2[0].text_content())

                    source_code3 = get_balance3(bech32)
                    received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid3 = source_code3.xpath(received_id3)
                    totalReceived3 = str(receivedid3[0].text_content())
                    sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid3 = source_code3.xpath(sent_id3)
                    totalSent3 = str(sentid3[0].text_content())
                    balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid3 = source_code3.xpath(balance_id3)
                    balance3 = str(balanceid3[0].text_content())
                    txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid3 = source_code3.xpath(txs_id3)
                    txs3 = str(txsid3[0].text_content())

                    n = "\n"
                    print('[purple] HEX Entered  >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] DEC Returned  >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('BTC Address : ', caddr)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
                    print('BTC Address : ', uaddr)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance1) + '][/green] totalReceived: [green][' +  str(totalReceived1) + '][/green] totalSent:[green][' + str(totalSent1) + '][/green] txs :[green][' + str(txs1) + '][/green]')
                    print('BTC Address : ', p2sh)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived2) + '][/green] totalSent:[green][' + str(totalSent2) + '][/green] txs :[green][' + str(txs2) + '][/green]')
                    print('BTC Address : ', bech32)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived3) + '][/green] totalSent:[green][' + str(totalSent3) + '][/green] txs :[green][' + str(txs3) + '][/green]')

                    bot.send_message(message.chat.id, (f" 🔨 HEX Entered  >> 🔨 {n}{HEX}{n}{n} ⛏️ DEC Returned  >> ⛏️ {n}{dec}  bits {length}{n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs} {n}{n} ₿itcoin Address = {uaddr} {n}{n}      💰 Balance 💰 {balance1}  BTC {n}      💸 TotalReceived 💸 {totalReceived1} {n}      📤 TotalSent 📤 {totalSent1} {n}      💵 Transactions 💵 {txs1}{n}{n} ₿itcoin Address = {p2sh} {n}{n}      💰 Balance 💰 {balance2}  BTC {n}      💸 TotalReceived 💸 {totalReceived2} {n}      📤 TotalSent 📤 {totalSent2} {n}      💵 Transactions 💵 {txs2}{n}{n} ₿itcoin Address = {bech32} {n}{n}      💰 Balance 💰 {balance3}  BTC {n}      💸 TotalReceived 💸 {totalReceived3} {n}      📤 TotalSent 📤 {totalSent3} {n}      💵 Transactions 💵 {txs3}{n}"))
                    if str(balance) != ammount or str(balance1) != ammount or str(balance2) != ammount or str(balance3) != ammount:
                        with open("data.txt", "a", encoding="utf-8") as f:
                            f.write(f"""{n} HEX Entered  >>{HEX}{n} DEC Returned  >> {dec}  bits {length}{n} WIF Compressed  >> {wifc}{n} WIF Uncompressed  >> {wifu}{n} Bitcoin Address = {caddr} Balance  {balance}  BTC TotalReceived {totalReceived}  TotalSent  {totalSent} Transactions  {txs} {n} Bitcoin Address = {uaddr} Balance  {balance1}  BTC TotalReceived  {totalReceived1} TotalSent  {totalSent1} Transactions  {txs1}{n} Bitcoin Address = {p2sh} Balance  {balance2}  BTC TotalReceived  {totalReceived2} TotalSent  {totalSent2} Transactions  {txs2}{n}Bitcoin Address = {bech32} Balance  {balance3}  BTC TotalReceived  {totalReceived3} TotalSent  {totalSent3} Transactions  {txs3}""")
                else:
                    bot.send_message(message.chat.id, "🚫 HEX OUT OF RANGE 🤪 Must be Lower Than FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 ")
                    start(message)
            elif checkHex(HEX)==False:
                bot.send_message(message.chat.id, "🚫 HEX Entered is not valid 🤪")
                print('[red] HEX Entered is not valid [/red]')
        else:
            bot.send_message(message.chat.id, "🚫 HEX Entered is not valid 🤪 Send in text format")
        start(message)

def get_DEC(message):
    if message.text=="🔙Back":
        start(message)
    else:
        string = message.text
        if message.content_type == "text":
            try:
                val = int(string)
                dec=int(val)
                if dec < maxN:
                    ammount = '0 BTC'
                    HEX = "%064x" % dec
                    length = len(bin(dec))
                    length -=2
                    print('\nDecimal = ',dec, '  bits ', length, '\nTo Hexadecimal = ', HEX)
                    wifc = ice.btc_pvk_to_wif(HEX)
                    wifu = ice.btc_pvk_to_wif(HEX, False)
                    caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                    uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                    p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                    bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                    
                    source_code = get_balance(caddr)
                    received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid = source_code.xpath(received_id)
                    totalReceived = str(receivedid[0].text_content())
                    sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid = source_code.xpath(sent_id)
                    totalSent = str(sentid[0].text_content())
                    balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid = source_code.xpath(balance_id)
                    balance = str(balanceid[0].text_content())
                    txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid = source_code.xpath(txs_id)
                    txs = str(txsid[0].text_content())

                    source_code1 = get_balance1(uaddr)
                    received_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid1 = source_code1.xpath(received_id1)
                    totalReceived1 = str(receivedid1[0].text_content())
                    sent_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid1 = source_code1.xpath(sent_id1)
                    totalSent1 = str(sentid1[0].text_content())
                    balance_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid1 = source_code1.xpath(balance_id1)
                    balance1 = str(balanceid1[0].text_content())
                    txs_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid1 = source_code1.xpath(txs_id1)
                    txs1 = str(txsid1[0].text_content())

                    source_code2 = get_balance2(p2sh)
                    received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid2 = source_code2.xpath(received_id2)
                    totalReceived2 = str(receivedid2[0].text_content())
                    sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid2 = source_code2.xpath(sent_id2)
                    totalSent2 = str(sentid2[0].text_content())
                    balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid2 = source_code2.xpath(balance_id2)
                    balance2 = str(balanceid2[0].text_content())
                    txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid2 = source_code2.xpath(txs_id2)
                    txs2 = str(txsid2[0].text_content())

                    source_code3 = get_balance3(bech32)
                    received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
                    receivedid3 = source_code3.xpath(received_id3)
                    totalReceived3 = str(receivedid3[0].text_content())
                    sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
                    sentid3 = source_code3.xpath(sent_id3)
                    totalSent3 = str(sentid3[0].text_content())
                    balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
                    balanceid3 = source_code3.xpath(balance_id3)
                    balance3 = str(balanceid3[0].text_content())
                    txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
                    txsid3 = source_code3.xpath(txs_id3)
                    txs3 = str(txsid3[0].text_content())
                    
                    n = "\n"
                    print('[purple] DEC Entered  >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] HEX Returned  >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('BTC Address : ', caddr)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
                    print('BTC Address : ', uaddr)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance1) + '][/green] totalReceived: [green][' +  str(totalReceived1) + '][/green] totalSent:[green][' + str(totalSent1) + '][/green] txs :[green][' + str(txs1) + '][/green]')
                    print('BTC Address : ', p2sh)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived2) + '][/green] totalSent:[green][' + str(totalSent2) + '][/green] txs :[green][' + str(txs2) + '][/green]')
                    print('BTC Address : ', bech32)
                    print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived3) + '][/green] totalSent:[green][' + str(totalSent3) + '][/green] txs :[green][' + str(txs3) + '][/green]')
                    
                    bot.send_message(message.chat.id, (f" ⛏️ DEC Entered  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 HEX Returned  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs} {n}{n} ₿itcoin Address = {uaddr} {n}{n}      💰 Balance 💰 {balance1}  BTC {n}      💸 TotalReceived 💸 {totalReceived1} {n}      📤 TotalSent 📤 {totalSent1} {n}      💵 Transactions 💵 {txs1}{n}{n} ₿itcoin Address = {p2sh} {n}{n}      💰 Balance 💰 {balance2}  BTC {n}      💸 TotalReceived 💸 {totalReceived2} {n}      📤 TotalSent 📤 {totalSent2} {n}      💵 Transactions 💵 {txs2}{n}{n} ₿itcoin Address = {bech32} {n}{n}      💰 Balance 💰 {balance3}  BTC {n}      💸 TotalReceived 💸 {totalReceived3} {n}      📤 TotalSent 📤 {totalSent3} {n}      💵 Transactions 💵 {txs3}{n}"))
                    if str(balance) != ammount or str(balance1) != ammount or str(balance2) != ammount or str(balance3) != ammount:
                        with open("data.txt", "a", encoding="utf-8") as f:
                            f.write(f"""{n} DEC Entered  >>{dec}{n} HEX Returned  >> {HEX}  bits {length}{n} WIF Compressed  >> {wifc}{n} WIF Uncompressed  >> {wifu}{n} Bitcoin Address = {caddr} Balance  {balance}  BTC TotalReceived {totalReceived}  TotalSent  {totalSent} Transactions  {txs} {n} Bitcoin Address = {uaddr} Balance  {balance1}  BTC TotalReceived  {totalReceived1} TotalSent  {totalSent1} Transactions  {txs1}{n} Bitcoin Address = {p2sh} Balance  {balance2}  BTC TotalReceived  {totalReceived2} TotalSent  {totalSent2} Transactions  {txs2}{n}Bitcoin Address = {bech32} Balance  {balance3}  BTC TotalReceived  {totalReceived3} TotalSent  {totalSent3} Transactions  {txs3}""")
                else:
                    bot.send_message(message.chat.id, "🚫 DEC OUT OF RANGE 🤪 Must be Lower than 115792089237316195423570985008687907852837564279074904382605163141518161494336 BITS256")
                    start(message)            
            except ValueError:
                bot.send_message(message.chat.id, "⚠️⛔ Invalid DEC Something Has Gone Wrong ⚠️⛔")
                print('[red]Invalid DEC Something Has Gone Wrong[/red]')
        else:
            bot.send_message(message.chat.id, "🚫 Invalid DEC Something Has Gone Wrong 🤪 Send in text format")
        start(message)

def get_BRAIN(message):
    if message.text=="🔙Back":
        start(message)
    if message.content_type == "text":
        passphrase = message.text
        wallet = BrainWallet()
        private_key, addr = wallet.generate_address_from_passphrase(passphrase)
        urlblock = "https://bitcoin.atomicwallet.io/address/" + addr
        respone_block = requests.get(urlblock)
        if respone_block.status_code==200:
            byte_string = respone_block.content
            source_code = html.fromstring(byte_string)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            n = "\n"
            bot.send_message(message.chat.id, f"      🧠 BrainWallet Entered 🤯{n}{n} {passphrase} {n}{n}      🕵️ Private Key In HEX 🕵️ {n} {private_key} {n}{n}      👇 ₿itcoin Adress 👇{n} {addr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs}")
            print('\nPassphrase     = ',passphrase)
            print('Private Key      = ',private_key)
            print('[purple] Bitcoin Address  >> [ [/purple]', addr , '[purple]][/purple]')
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            if str(balance) != ammount:
                with open("data.txt", "a", encoding="utf-8") as f:
                    f.write(f"""{n}BrainWallet Entered {passphrase} {n} Private Key In HEX {private_key} {n} Bitcoin Adress {addr} Balance  {balance}  BTC TotalReceived  {totalReceived} TotalSent  {totalSent} Transactions  {txs}""")
        else:
            bot.send_message(message.chat.id, "🤯🧠Something Has Gone Wrong with your Brain🧠🤯")
            print('[red]Something Has Gone Wrong with your Brain[/red]')
    else:
        bot.send_message(message.chat.id, "🤯🧠Something Has Gone Wrong with your Brain🧠🤯 Send in text format")
    start(message)

def get_BRAIN_RANDOM(message):
    if message.text=="🔙Back":
        start(message)
    else:
        if message.text=="1-3 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(1,3)))
        if message.text=="3-6 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(3,6)))
        if message.text=="6-9 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(6,9)))
        if message.text=="9-12 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(9,12)))
        if message.text=="12-15 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(12,15)))
        if message.text=="15-18 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(15,18)))
        if message.text=="18-21 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(18,21)))
        if message.text=="21-24 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(21,24)))
        if message.text=="24-50 Words":
            passphrase = ' '.join(random.sample(mylist, random.randint(24,50)))
        wallet = BrainWallet()
        private_key, addr = wallet.generate_address_from_passphrase(passphrase)
        urlblock = "https://bitcoin.atomicwallet.io/address/" + addr
        respone_block = requests.get(urlblock)
        if respone_block.status_code==200:
            byte_string = respone_block.content
            source_code = html.fromstring(byte_string)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())
            n = "\n"
            bot.send_message(message.chat.id, f"      🧠 BrainWallet Entered 🤯{n}{n} {passphrase} {n}{n}      🕵️ Private Key In HEX 🕵️ {n} {private_key} {n}{n}      👇 ₿itcoin Adress 👇{n} {addr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs}")
            print('\nPassphrase     = ',passphrase)
            print('Private Key      = ',private_key)
            print('[purple] Bitcoin Address  >> [ [/purple]', addr, '[purple]][/purple]')
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            if str(balance) != ammount:
                with open("data.txt", "a", encoding="utf-8") as f:
                    f.write(f"""{n}BrainWallet Entered {passphrase} {n} Private Key In HEX {private_key} {n} Bitcoin Adress {addr} Balance  {balance}  BTC TotalReceived  {totalReceived} TotalSent  {totalSent} Transactions  {txs}""")
        else:
            bot.send_message(message.chat.id, "🤯🧠Something Has Gone Wrong with your Brain🧠🤯")
            print('[red]Something Has Gone Wrong with your Brain[/red]')
        start(message)

def get_WIF(message):
    if message.text=="🔙Back":
        start(message)
    else:
        WIF = message.text
        if WIF.startswith('5H') or WIF.startswith('5J') or WIF.startswith('5K') or WIF.startswith('K') or WIF.startswith('L'):
            if WIF.startswith('5H') or WIF.startswith('5J') or WIF.startswith('5K'):
                first_encode = base58.b58decode(WIF)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
                private_key_hex = private_key.decode("utf-8")
                dec = int(private_key_hex,16)
                    
            elif WIF.startswith('K') or WIF.startswith('L'):
                first_encode = base58.b58decode(WIF)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
                private_key_hex = private_key.decode("utf-8")
                dec = int(private_key_hex[0:64],16)
            HEX = "%064x" % dec
            wifc = ice.btc_pvk_to_wif(HEX)
            wifu = ice.btc_pvk_to_wif(HEX, False) 
            uaddr = ice.privatekey_to_address(0, False, dec)
            caddr = ice.privatekey_to_address(0, True, dec) 
            p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
            bech32 = ice.privatekey_to_address(2, True, dec)  #bech32           
            length = len(bin(dec))
            length -=2
            print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)

            source_code = get_balance(caddr)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())

            source_code1 = get_balance1(uaddr)
            received_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid1 = source_code1.xpath(received_id1)
            totalReceived1 = str(receivedid1[0].text_content())
            sent_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid1 = source_code1.xpath(sent_id1)
            totalSent1 = str(sentid1[0].text_content())
            balance_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid1 = source_code1.xpath(balance_id1)
            balance1 = str(balanceid1[0].text_content())
            txs_id1 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid1 = source_code1.xpath(txs_id1)
            txs1 = str(txsid1[0].text_content())

            source_code2 = get_balance2(p2sh)
            received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid2 = source_code2.xpath(received_id2)
            totalReceived2 = str(receivedid2[0].text_content())
            sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid2 = source_code2.xpath(sent_id2)
            totalSent2 = str(sentid2[0].text_content())
            balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid2 = source_code2.xpath(balance_id2)
            balance2 = str(balanceid2[0].text_content())
            txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid2 = source_code2.xpath(txs_id2)
            txs2 = str(txsid2[0].text_content())

            source_code3 = get_balance3(bech32)
            received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid3 = source_code3.xpath(received_id3)
            totalReceived3 = str(receivedid3[0].text_content())
            sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid3 = source_code3.xpath(sent_id3)
            totalSent3 = str(sentid3[0].text_content())
            balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid3 = source_code3.xpath(balance_id3)
            balance3 = str(balanceid3[0].text_content())
            txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid3 = source_code3.xpath(txs_id3)
            txs3 = str(txsid3[0].text_content())
            
            n = "\n"
            print('[purple] WIF Entered  >> [ [/purple]', WIF, '[purple]][/purple]')
            print('[purple] HEX Returned  >> [ [/purple]', HEX, '[purple]][/purple]')
            print('[purple] DEC Returned  >> [ [/purple]', dec, '[purple]][/purple]')
            print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
            print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
            print('BTC Address : ', caddr)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            print('BTC Address : ', uaddr)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance1) + '][/green] totalReceived: [green][' +  str(totalReceived1) + '][/green] totalSent:[green][' + str(totalSent1) + '][/green] txs :[green][' + str(txs1) + '][/green]')
            print('BTC Address : ', p2sh)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived2) + '][/green] totalSent:[green][' + str(totalSent2) + '][/green] txs :[green][' + str(txs2) + '][/green]')
            print('BTC Address : ', bech32)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived3) + '][/green] totalSent:[green][' + str(totalSent3) + '][/green] txs :[green][' + str(txs3) + '][/green]')
            bot.send_message(message.chat.id, (f" 🔥 WIF Entered  >> 🔥 {n}{WIF}  {n}{n}🔨 HEX Returned  >> 🔨{n}{HEX} {n}{n}⛏️ DEC Returned  >> ⛏️ {n}{dec}  bits {length} {n}{n}🗝️ WIF Compressed  >> 🗝️{wifc} {n}{n} 🔑 WIF Uncompressed  >>  🔑 {n}{wifu} {n}{n} ₿itcoin Address = {caddr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs} {n}{n} ₿itcoin Address = {uaddr} {n}{n}      💰 Balance 💰 {balance1}  BTC {n}      💸 TotalReceived 💸 {totalReceived1} {n}      📤 TotalSent 📤 {totalSent1} {n}      💵 Transactions 💵 {txs1} {n}{n} ₿itcoin Address = {p2sh} {n}{n}      💰 Balance 💰 {balance2}  BTC {n}      💸 TotalReceived 💸 {totalReceived2} {n}      📤 TotalSent 📤 {totalSent2} {n}      💵 Transactions 💵 {txs2}{n}{n} ₿itcoin Address = {bech32} {n}{n}      💰 Balance 💰 {balance3}  BTC {n}      💸 TotalReceived 💸 {totalReceived3} {n}      📤 TotalSent 📤 {totalSent3} {n}      💵 Transactions 💵 {txs3}{n}"))
            if str(balance) != ammount or str(balance1) != ammount or str(balance2) != ammount or str(balance3) != ammount:
                with open("data.txt", "a", encoding="utf-8") as f:
                    f.write(f"""{n} WIF Entered  >>  {WIF} {n} HEX Returned  >>{HEX}{n} DEC Returned  >> {dec}  bits {length}{n} WIF Compressed  >> {wifc}{n} WIF Uncompressed  >> {wifu}{n} Bitcoin Address = {addressinfo} Balance  {balance}  BTC TotalReceived {totalReceived}  TotalSent  {totalSent} Transactions  {txs} {n} Bitcoin Address = {addressinfo1} Balance  {balance1}  BTC TotalReceived  {totalReceived1} TotalSent  {totalSent1} Transactions  {txs1}{n} Bitcoin Address = {addressinfo2} Balance  {balance2}  BTC TotalReceived  {totalReceived2} TotalSent  {totalSent2} Transactions  {txs2}{n}Bitcoin Address = {addressinfo3} Balance  {balance3}  BTC TotalReceived  {totalReceived3} TotalSent  {totalSent3} Transactions  {txs3}""")
        else:
            bot.send_message(message.chat.id, "⚠️⛔ Invalid WIF Try Again ⛔⚠️")
            print('[red]Invalid WIF Try Again[/red]')
        start(message)

def get_WORDS(message):                    
    if message.text=="🔙Back":
        start(message)
    else:
        derivation_total_path_to_check = 1
        n = "\n"
        if message.text=="✨12 Word ️Mnenomic✨":
            mnem = create_valid_mnemonics(strength=128)
            seed = mnem_to_seed(mnem)
            pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
            pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
            pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
            caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
            p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
            bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
            
            source_code = get_balance(caddr)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())

            source_code2 = get_balance2(p2sh)
            received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid2 = source_code2.xpath(received_id2)
            totalReceived2 = str(receivedid2[0].text_content())
            sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid2 = source_code2.xpath(sent_id2)
            totalSent2 = str(sentid2[0].text_content())
            balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid2 = source_code2.xpath(balance_id2)
            balance2 = str(balanceid2[0].text_content())
            txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid2 = source_code2.xpath(txs_id2)
            txs2 = str(txsid2[0].text_content())

            source_code3 = get_balance3(bech32)
            received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid3 = source_code3.xpath(received_id3)
            totalReceived3 = str(receivedid3[0].text_content())
            sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid3 = source_code3.xpath(sent_id3)
            totalSent3 = str(sentid3[0].text_content())
            balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid3 = source_code3.xpath(balance_id3)
            balance3 = str(balanceid3[0].text_content())
            txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid3 = source_code3.xpath(txs_id3)
            txs3 = str(txsid3[0].text_content())

            print('[purple] Mnemonics Words 12 (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
            print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
            print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
            print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
            print('BTC Address : ', caddr)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            print('BTC Address : ', p2sh)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived2) + '][/green] totalSent:[green][' + str(totalSent2) + '][/green] txs :[green][' + str(txs2) + '][/green]')
            print('BTC Address : ', bech32)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived3) + '][/green] totalSent:[green][' + str(totalSent3) + '][/green] txs :[green][' + str(txs3) + '][/green]')
            bot.send_message(message.chat.id, (f" Mnemonics Words 12 (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs} {n}{n} ₿itcoin Address = {p2sh} {n}{n}      💰 Balance 💰 {balance2}  BTC {n}      💸 TotalReceived 💸 {totalReceived2} {n}      📤 TotalSent 📤 {totalSent2} {n}      💵 Transactions 💵 {txs2}{n}{n} ₿itcoin Address = {bech32} {n}{n}      💰 Balance 💰 {balance3}  BTC {n}      💸 TotalReceived 💸 {totalReceived3} {n}      📤 TotalSent 📤 {totalSent3} {n}      💵 Transactions 💵 {txs3}{n}"))
            if str(balance) != ammount or str(balance2) != ammount or str(balance3) != ammount:
                with open("data.txt", "a", encoding="utf-8") as f:
                    f.write(f"""{n} Mnemonics Words 12 (English)  >> {n} {mnem} {n} Bitcoin Address = {addressinfo} Balance  {balance}  BTC TotalReceived {totalReceived}  TotalSent  {totalSent} Transactions  {txs} {n} Bitcoin Address = {addressinfo2} Balance  {balance2}  BTC TotalReceived  {totalReceived2} TotalSent  {totalSent2} Transactions  {txs2}{n}Bitcoin Address = {addressinfo3} Balance  {balance3}  BTC TotalReceived  {totalReceived3} TotalSent  {totalSent3} Transactions  {txs3}""")        
            
        elif message.text=="✨24 Word ️Mnenomic✨":
            mnem = create_valid_mnemonics(strength=256)
            seed = mnem_to_seed(mnem)
            pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
            pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
            pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
            caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
            p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
            bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
            
            source_code = get_balance(caddr)
            received_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid = source_code.xpath(received_id)
            totalReceived = str(receivedid[0].text_content())
            sent_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid = source_code.xpath(sent_id)
            totalSent = str(sentid[0].text_content())
            balance_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid = source_code.xpath(balance_id)
            balance = str(balanceid[0].text_content())
            txs_id = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid = source_code.xpath(txs_id)
            txs = str(txsid[0].text_content())

            source_code2 = get_balance2(p2sh)
            received_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid2 = source_code2.xpath(received_id2)
            totalReceived2 = str(receivedid2[0].text_content())
            sent_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid2 = source_code2.xpath(sent_id2)
            totalSent2 = str(sentid2[0].text_content())
            balance_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid2 = source_code2.xpath(balance_id2)
            balance2 = str(balanceid2[0].text_content())
            txs_id2 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid2 = source_code2.xpath(txs_id2)
            txs2 = str(txsid2[0].text_content())

            source_code3 = get_balance3(bech32)
            received_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[1]/td[2]'
            receivedid3 = source_code3.xpath(received_id3)
            totalReceived3 = str(receivedid3[0].text_content())
            sent_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[2]/td[2]'
            sentid3 = source_code3.xpath(sent_id3)
            totalSent3 = str(sentid3[0].text_content())
            balance_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[3]/td[2]'
            balanceid3 = source_code3.xpath(balance_id3)
            balance3 = str(balanceid3[0].text_content())
            txs_id3 = '/html/body/main/div/div[2]/div[1]/table/tbody/tr[4]/td[2]'
            txsid3 = source_code3.xpath(txs_id3)
            txs3 = str(txsid3[0].text_content())

            print('[purple] Mnemonics 24 Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
            print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
            print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
            print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
            print('BTC Address : ', caddr)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
            print('BTC Address : ', p2sh)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived2) + '][/green] totalSent:[green][' + str(totalSent2) + '][/green] txs :[green][' + str(txs2) + '][/green]')
            print('BTC Address : ', bech32)
            print('[red][*][/red] [purple] >>[/purple] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived3) + '][/green] totalSent:[green][' + str(totalSent3) + '][/green] txs :[green][' + str(txs3) + '][/green]')
            bot.send_message(message.chat.id, (f" Mnemonics 24 Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n}      💰 Balance 💰 {balance}  BTC {n}      💸 TotalReceived 💸 {totalReceived} {n}      📤 TotalSent 📤 {totalSent} {n}      💵 Transactions 💵 {txs} {n}{n} ₿itcoin Address = {p2sh} {n}{n}      💰 Balance 💰 {balance2}  BTC {n}      💸 TotalReceived 💸 {totalReceived2} {n}      📤 TotalSent 📤 {totalSent2} {n}      💵 Transactions 💵 {txs2}{n}{n} ₿itcoin Address = {bech32} {n}{n}      💰 Balance 💰 {balance3}  BTC {n}      💸 TotalReceived 💸 {totalReceived3} {n}      📤 TotalSent 📤 {totalSent3} {n}      💵 Transactions 💵 {txs3}{n}"))
            if str(balance) != ammount or str(balance2) != ammount or str(balance3) != ammount:
                with open("data.txt", "a", encoding="utf-8") as f:
                    f.write(f"""{n} Mnemonics Words 12 (English)  >> {n} {mnem} {n} Bitcoin Address = {addressinfo} Balance  {balance}  BTC TotalReceived {totalReceived}  TotalSent  {totalSent} Transactions  {txs} {n} Bitcoin Address = {addressinfo2} Balance  {balance2}  BTC TotalReceived  {totalReceived2} TotalSent  {totalSent2} Transactions  {txs2}{n}Bitcoin Address = {addressinfo3} Balance  {balance3}  BTC TotalReceived  {totalReceived3} TotalSent  {totalSent3} Transactions  {txs3}""")
        else:
            bot.send_message(message.chat.id, "⚠️⛔ Invalid WORDS Try Again ⛔⚠️")
            print('[red]Invalid WORDS Try Again[/red]')
        start(message)
      
def get_POWER(message):
    if message.text=="🔙Back":
        start(message)
    else:
        count = 0
        total = 0
        num = 1
        derivation_total_path_to_check = 1
        if message.text=="1 Minutes Magic Random Words":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄1 Minutes Magic Random Words 🪄"))
            print('[yellow]\n---------------------1 Minutes Magic Random Words---------------------------------[/yellow]')
            print(ICEWORDS)
            print('[yellow]\n---------------------1 Minutes Magic Random Words---------------------------------[/yellow]')
            t_end = time.time() + 60 * 1
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                finish= 0
                count += 1
                total += 4
                lenght= ('128','256')
                rnds = random.choice(lenght)
                mnem = create_valid_mnemonics(strength=int(rnds))
                seed = mnem_to_seed(mnem)
                pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
                pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
                pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
                pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Mnemonics [/purple]',rnds, '[purple] Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nMnemonics: ' + mnem)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic ETH Address   : ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n}  Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 "))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} "))
                        num += 1

        if message.text=="5 Minutes Magic Random Words":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄5 Minutes Magic Random Words 🪄"))
            print('[yellow]\n---------------------5 Minutes Magic Random Words---------------------------------[/yellow]')
            print(ICEWORDS)
            print('[yellow]\n---------------------5 Minutes Magic Random Words---------------------------------[/yellow]')
            t_end = time.time() + 60 * 5
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                finish= 0
                count += 1
                total += 4
                lenght= ('128','256')
                rnds = random.choice(lenght)
                mnem = create_valid_mnemonics(strength=int(rnds))
                seed = mnem_to_seed(mnem)
                pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
                pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
                pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
                pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Mnemonics [/purple]',rnds, '[purple] Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nMnemonics: ' + mnem)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic ETH Address   : ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n}  Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 "))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} "))
                        num += 1
                
        if message.text=="15 Minutes Magic Random Words ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄15 Minutes Magic Random Words 🪄✨(Pro Access)✨"))
            print('[yellow]\n---------------------15 Minutes Magic Random Words---------------------------------[/yellow]')
            print(ICEWORDS)
            print('[yellow]\n---------------------15 Minutes Magic Random Words---------------------------------[/yellow]')
            t_end = time.time() + 60 * 15
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                finish= 0
                count += 1
                total += 4
                lenght= ('128','256')
                rnds = random.choice(lenght)
                mnem = create_valid_mnemonics(strength=int(rnds))
                seed = mnem_to_seed(mnem)
                pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
                pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
                pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
                pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Mnemonics [/purple]',rnds, '[purple] Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nMnemonics: ' + mnem)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic ETH Address   : ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n}  Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 "))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} "))
                        num += 1
        if message.text=="30 Minutes Magic Random Words ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄30 Minutes Magic Random Words 🪄✨(Pro Access)✨"))
            print('[purple]\n---------------------30 Minutes Magic Random Words(Pro Access)---------------------------------[/purple]')
            print(ICEWORDS)
            print('[purple]\n---------------------30 Minutes Magic Random Words(Pro Access)---------------------------------[/purple]')
            t_end = time.time() + 60 * 30
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                finish= 0
                count += 1
                total += 4
                lenght= ('128','256')
                rnds = random.choice(lenght)
                mnem = create_valid_mnemonics(strength=int(rnds))
                seed = mnem_to_seed(mnem)
                pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
                pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
                pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
                pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Mnemonics [/purple]',rnds, '[purple] Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nMnemonics: ' + mnem)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic ETH Address   : ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n}  Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 "))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} "))
                        num += 1
        if message.text=="1 Hour Magic Random Words ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄1 Hour Magic Random Words 🪄✨(Pro Access)✨"))
            print('[purple]\n---------------------1 Hour Magic Random Words(Pro Access)---------------------------------[/purple]')
            print(ICEWORDS)
            print('[purple]\n---------------------1 Hour Magic Random Words(Pro Access)---------------------------------[/purple]')
            t_end = time.time() + 60 * 60
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                finish= 0
                count += 1
                total += 4
                lenght= ('128','256')
                rnds = random.choice(lenght)
                mnem = create_valid_mnemonics(strength=int(rnds))
                seed = mnem_to_seed(mnem)
                pvk = bip39seed_to_private_key(seed, derivation_total_path_to_check)
                pvk2 = bip39seed_to_private_key2(seed, derivation_total_path_to_check)
                pvk3 = bip39seed_to_private_key3(seed, derivation_total_path_to_check)
                pvk4 = bip39seed_to_private_key4(seed, derivation_total_path_to_check)
                caddr = ice.privatekey_to_address(0, True, (int.from_bytes(pvk, "big")))
                p2sh = ice.privatekey_to_address(1, True, (int.from_bytes(pvk2, "big")))
                bech32 = ice.privatekey_to_address(2, True, (int.from_bytes(pvk3, "big")))
                ethaddr = ice.privatekey_to_ETH_address(int.from_bytes(pvk4, "big"))
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Mnemonics [/purple]',rnds, '[purple] Words (English)  >> [ [/purple]', mnem, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nMnemonics: ' + mnem)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic ETH Address   : ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n}  Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 "))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} Mnemonics {rnds} Words (English)  >> {n} {mnem}  {n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} ETH Address = {ethaddr} "))
                        num += 1
        else:
            bot.send_message(message.chat.id, "Going back to the Main Menu ")
            print('[red]Going back to the Main Menu[/red]')
        start(message)

def get_POWER_FULLRANGE(message):
    if message.text=="🔙Back":
        start(message)
    else:
        count = 0
        total = 0
        num = 1
        n = "\n"
        startscan=2**1
        stopscan=2**256
        print(FULLRANGE)
        if message.text=="1 Minutes Magic Random Range":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄1 Minutes Magic Random Range 🪄"))
            print('[yellow]\n---------------------1 Minutes Magic Random Range---------------------------------[/yellow]')
            
            t_end = time.time() + 60 * 1
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    #print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr}"))
                        num += 1

        if message.text=="5 Minutes Magic Random Range":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄5 Minutes Magic Random Range 🪄"))
            print('[yellow]\n---------------------5 Minutes Magic Random Range---------------------------------[/yellow]')
            t_end = time.time() + 60 * 5
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    #print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr}"))
                        num += 1
                
        if message.text=="15 Minutes Magic Random Range ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄15 Minutes Magic Random Range 🪄✨(Pro Access)✨"))
            print('[yellow]\n---------------------15 Minutes Magic Random Range---------------------------------[/yellow]')
            t_end = time.time() + 60 * 15
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    #print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr}"))
                        num += 1
                        
        if message.text=="30 Minutes Magic Random Range ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄30 Minutes Magic Random Range 🪄✨(Pro Access)✨"))
            print('[purple]\n---------------------30 Minutes Magic Random Range(Pro Access)---------------------------------[/purple]')
            t_end = time.time() + 60 * 30
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    #print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr}"))
                        num += 1
                        
        if message.text=="1 Hour Magic Random Range ✨(Pro Access)✨":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄1 Hour Magic Random Range 🪄✨(Pro Access)✨"))
            print('[purple]\n---------------------1 Hour Magic Random Range(Pro Access)---------------------------------[/purple]')
            t_end = time.time() + 60 * 60
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    #print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr}"))
                        num += 1
        else:
            bot.send_message(message.chat.id, "Going back to the Main Menu ")
            print('[red]Going back to the Main Menu[/red]')
        start(message)

def get_POWER_RANGE(message):
    if message.text=="🔙Back":
        start(message)
    else:
        count = 0
        total = 0
        num = 1
        n = "\n"
        print(RANGER)
        if message.text=="1-64 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 1-64 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------1-64 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**1
                stopscan=2**64
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 1-64 Bits Random Range"))
                        num += 1
        if message.text=="64-70 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 64-70 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------64-70 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**64
                stopscan=2**70
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 64-70 Bits Random Range"))
                        num += 1
        
        if message.text=="70-80 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 70-80 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------70-80 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**70
                stopscan=2**80
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 70-80 Bits Random Range"))
                        num += 1
        
        if message.text=="80-90 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 80-90 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------80-90 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**80
                stopscan=2**90
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 80-90 Bits Random Range"))
                        num += 1
                        
        if message.text=="90-100 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 90-100 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------90-100 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**90
                stopscan=2**100
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 90-100 Bits Random Range"))
                        num += 1
        
        if message.text=="100-110 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 100-110 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------100-110 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**100
                stopscan=2**110
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 100-110 Bits Random Range"))
                        num += 1
                        
        if message.text=="110-120 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 110-120 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------110-120 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**110
                stopscan=2**120
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 110-120 Bits Random Range"))
                        num += 1
                        
        if message.text=="120-130 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 120-130 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------120-130 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**120
                stopscan=2**130
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 120-130 Bits Random Range"))
                        num += 1
        
        if message.text=="130-140 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 130-140 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------130-140 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**130
                stopscan=2**140
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 130-140 Bits Random Range"))
                        num += 1
                        
        if message.text=="140-150 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 140-150 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------140-150 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**140
                stopscan=2**150
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 140-150 Bits Random Range"))
                        num += 1
                        
        if message.text=="150-160 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 150-160 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------150-160 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**150
                stopscan=2**160
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 150-160 Bits Random Range"))
                        num += 1
                        
        if message.text=="160-170 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 160-170 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------160-170 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**160
                stopscan=2**170
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 160-170 Bits Random Range"))
                        num += 1
        
        if message.text=="170-180 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 170-180 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------170-180 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**170
                stopscan=2**180
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 170-180 Bits Random Range"))
                        num += 1
                        
        if message.text=="180-190 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 180-190 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------180-190 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**180
                stopscan=2**190
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 180-190 Bits Random Range"))
                        num += 1

        if message.text=="190-200 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 190-200 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------190-200 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**190
                stopscan=2**200
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 190-200 Bits Random Range"))
                        num += 1

        if message.text=="200-210 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 200-210 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------200-210 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**200
                stopscan=2**210
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 200-210 Bits Random Range"))
                        num += 1

        if message.text=="210-220 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 210-220 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------210-220 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**210
                stopscan=2**220
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 210-220 Bits Random Range"))
                        num += 1

        if message.text=="220-230 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 220-230 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------220-230 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**220
                stopscan=2**230
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 220-230 Bits Random Range"))
                        num += 1

        if message.text=="230-240 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 230-240 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------230-240 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**230
                stopscan=2**240
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 230-240 Bits Random Range"))
                        num += 1

        if message.text=="240-250 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 240-250 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------240-250 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**240
                stopscan=2**250
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 240-250 Bits Random Range"))
                        num += 1

        if message.text=="250-253 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 250-253 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------250-253 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**250
                stopscan=2**253
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 250-253 Bits Random Range"))
                        num += 1

        if message.text=="253-255 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 253-255 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------253-255 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**253
                stopscan=2**255
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 253-255 Bits Random Range"))
                        num += 1

        if message.text=="255-256 Bits":
            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} 🤞🍀 Good Luck and Happy Hunting 🍀🤞 {n}{n} 🪄 255-256 Bits Magic Random Range This will run for 2mins 🪄"))
            print('[yellow]\n---------------------255-256 Bits Random Range ---------------------------------[/yellow]')
            t_end = time.time() + 60 * 2
            t = time.localtime()
            current_time = time.strftime("%H:%M:%S", t)
            while time.time() < t_end:
                count += 1
                total += 4
                startscan=2**255
                stopscan=2**256
                ran=random.randrange(startscan,stopscan)
                dec = str(ran)
                HEX = "%064x" % ran
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, int(dec)) #Compressed
                uaddr = ice.privatekey_to_address(0, False, int(dec))  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, int(dec)) #p2sh
                bech32 = ice.privatekey_to_address(2, True, int(dec))  #bech32
                ethaddr = ice.privatekey_to_ETH_address(int(dec))            
                length = len(bin(int(dec)))
                length -=2
                if caddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('[purple] Private Key DEC   >> [ [/purple]', dec, '[purple]][/purple]')
                    print('[purple] Private Key HEX   >> [ [/purple]', HEX, '[purple]][/purple]')
                    print('[purple] WIF Compressed  >> [ [/purple]', wifc, '[purple]][/purple]')
                    print('[purple] WIF Uncompressed  >> [ [/purple]', wifu, '[purple]][/purple]')
                    print('[purple] BTC Compressed  >> [ [/purple]', caddr, '[purple]][/purple]')
                    print('[purple] BTC UnCompressed  >> [ [/purple]', uaddr, '[purple]][/purple]')
                    print('[purple] BTC p2sh  >> [ [/purple]', p2sh, '[purple]][/purple]')
                    print('[purple] BTC Bc1  >> [ [/purple]', bech32, '[purple]][/purple]')
                    print('[purple] ETH Address  >> [ [/purple]', ethaddr, '[purple]][/purple]')
                    f=open("winner.txt","a")
                    f.write('\nPrivatekey (dec): ' + str(dec))
                    f.write('\nPrivatekey (hex): ' + HEX)
                    f.write('\nPrivatekey compressed: ' + wifc)
                    f.write('\nPrivatekey Uncompressed: ' + wifu)
                    f.write('\nPublic Address 1 Compressed: ' + caddr)
                    f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                    f.write('\nPublic Address 3 P2SH: ' + p2sh)
                    f.write('\nPublic Address bc1 BECH32: ' + bech32)
                    f.write('\nPublic Address ETH: ' + ethaddr)
                    f.close()
                    bot.send_message(message.chat.id, (f" 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸 {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 💸💰🤑WOW YOU HAVE FOUND!!!🤑💰💸"))

                else:
                    print('[purple]Scan Number [ [/purple]', str(count), '[purple] ] Total Checked [ [/purple]', str(total), '[purple] ]  [/purple] Start Time = ', current_time, end='\r')
                    if num in range(100000):
                        if num % 4000 == 0:
                            print('[yellow] SENDING MESSAGE TO TELEGRAM EVERY 4000 TIMES [/yellow]')
                            bot.send_message(message.chat.id, (f"SENDING MESSAGE TO TELEGRAM EVERY 4000 GENERATIONS {n}{n} Scan Number {count}  Total Addresses Scanned {total}  {n}{n} ⛏️ Private Key DEC  >> ⛏️{n}{dec}  bits {length}{n}{n} 🔨 Private Key HEX  >> 🔨{n}{HEX} {n}{n} 🗝️ WIF Compressed  >> 🗝️ {n}{wifc}{n}{n} 🔑 WIF Uncompressed  >> 🔑 {n}{wifu}{n}{n} ₿itcoin Address = {caddr} {n}{n} ₿itcoin Address = {uaddr} {n}{n} ₿itcoin Address = {p2sh} {n}{n} ₿itcoin Address = {bech32} {n}{n} Ethereum Address = {ethaddr} {n}{n} 255-256 Bits Random Range"))
                        num += 1
        else:
            bot.send_message(message.chat.id, "Going back to the Main Menu ")
            print('[red]Going back to the Main Menu[/red]')
        start(message)

bot.polling()

for i in range(10):
    t = threading.Thread(target=start)
    threads.append(t)
    t.start()
