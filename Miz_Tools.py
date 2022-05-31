#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json, requests, codecs, hashlib, ecdsa, bip32utils, binascii, sys, time, random, itertools, csv, base58
from bit import *
from bit.format import bytes_to_wif
from tqdm import tqdm
import secp256k1 as ice
from mnemonic import Mnemonic
from bloomfilter import BloomFilter, ScalableBloomFilter, SizeGrowthRate
from pathlib import Path
from urllib.request import urlopen
from time import sleep
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.derivations import BIP44Derivation
from hdwallet.utils import generate_mnemonic
from hdwallet import HDWallet
from typing import Optional
from hdwallet.symbols import ETH as SYMBOL
from rich import print

# =============================================================================
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
j=0
pbar=tqdm(initial=j)
# =============================================================================
def get_balance(caddr):
    contents = requests.get("https://btcbook.guarda.co/api/v2/address/" + caddr)
    res = contents.json()
    ress = json.dumps(res)
    resload = json.loads(ress)
    info = str(resload)
    balance = (resload['balance'])
    totalReceived = (resload['totalReceived'])
    totalSent = (resload['totalSent'])
    txs = (resload['txs'])
    addressinfo = (resload['address'])
    print('BTC Address : ', addressinfo)
    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
    return balance

    
def get_balance1(uaddr):
    contents = requests.get("https://btcbook.guarda.co/api/v2/address/" + uaddr)
    res = contents.json()
    ress = json.dumps(res)
    resload = json.loads(ress)
    info = str(resload)
    balance1 = (resload['balance'])
    totalReceived = (resload['totalReceived'])
    totalSent = (resload['totalSent'])
    txs = (resload['txs'])
    addressinfo = (resload['address'])
    print('BTC Address : ', addressinfo)
    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance1) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
    return balance1

def get_balance2(p2sh):
    contents = requests.get("https://btcbook.guarda.co/api/v2/address/" + p2sh)
    res = contents.json()
    ress = json.dumps(res)
    resload = json.loads(ress)
    info = str(resload)
    balance2 = (resload['balance'])
    totalReceived = (resload['totalReceived'])
    totalSent = (resload['totalSent'])
    txs = (resload['txs'])
    addressinfo = (resload['address'])
    print('BTC Address : ', addressinfo)
    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance2) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
    return balance2

def get_balance3(bech32):
    contents = requests.get("https://btcbook.guarda.co/api/v2/address/" + bech32)
    res = contents.json()
    ress = json.dumps(res)
    resload = json.loads(ress)
    info = str(resload)
    balance3 = (resload['balance'])
    totalReceived = (resload['totalReceived'])
    totalSent = (resload['totalSent'])
    txs = (resload['txs'])
    addressinfo = (resload['address'])
    print('BTC Address : ', addressinfo)
    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance3) + '][/green] totalReceived: [green][' +  str(totalReceived) + '][/green] totalSent:[green][' + str(totalSent) + '][/green] txs :[green][' + str(txs) + '][/green]')
    return balance3
    
def get_balance4(ethaddr):
    contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)
    res = contents.json()
    ress = json.dumps(res)
    resload = json.loads(ress)
    info = str(resload)
    balance4 = (resload['balance'])
    txs = (resload['txs'])
    addressinfo = (resload['address'])
    print('ETH Address : ', addressinfo)
    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance4) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
    return balance4
    
# =============================================================================
print('[yellow] Please with Database Loading.....[/yellow]')
bloombtc = Path(__file__).resolve()
ressbtc = bloombtc.parents[0] / 'BF/btc.bf'
bloometh = Path(__file__).resolve()
resseth = bloometh.parents[0] / 'BF/eth.bf'

with open(resseth, "rb") as fp:
    bloom_filter1 = BloomFilter.load(fp)   

with open(ressbtc, "rb") as fp:
    bloom_filter = BloomFilter.load(fp)

btc_count = len(bloom_filter)
eth_count = len(bloom_filter1)
addr_count = len(bloom_filter)+len(bloom_filter1)
print('[yellow] Total Bitcoin and ETH Addresses Loaded  >> [ [/yellow]', addr_count, '[yellow]][/yellow]')
# =============================================================================
def iter_all_front(count):
    if count == 0:
        yield ""
    else:
        for HEXIN in "0123456789abcdef":
            if count == HEXIN:
                continue
            else:
                for scan in iter_all_front(count-1):
                    yield HEXIN + scan
                    
def iter_all_back(count):
    if count == 0:
        yield ""
    else:
        for HEXIN in "0123456789abcdef":
            if count == HEXIN:
                continue
            else:
                for scan in iter_all_back(count-1):
                    yield scan + HEXIN

def save_data_plain():
    with open("winner.txt", "a", encoding="utf-8") as f:
        f.write(f"""\nPrivateKey (hex) : {HEX}
PrivateKey (dec) : {dec} : {length}Bits
PrivateKey (wif) Compressed   : {wifc}
PrivateKey (wif) UnCompressed : {wifu}
Bitcoin Address Compressed   = {caddr}
Bitcoin Address UnCompressed = {uaddr}
Bitcoin Address p2sh         = {p2sh}
Bitcoin Address Bc1  bech32  = {bech32}
ETH Address = {ethaddr}""")

def print_data_plain():
    print(f"""\nPrivateKey (hex) : {HEX}
PrivateKey (dec) : {dec} : {length}Bits
PrivateKey (wif) Compressed   : {wifc}
PrivateKey (wif) UnCompressed : {wifu}
Bitcoin Address Compressed   = {caddr}
Bitcoin Address UnCompressed = {uaddr}
Bitcoin Address p2sh         = {p2sh}
Bitcoin Address Bc1  bech32  = {bech32}
ETH Address = {ethaddr}""")
# =============================================================================
def data_info():
    blocs=requests.get("https://blockchain.info/rawaddr/"+caddr)
    ress = blocs.json()
    hash160 = dict(ress)["hash160"]
    address = dict(ress)["address"]
    n_tx = dict(ress)["n_tx"]
    total_received = dict(ress)["total_received"]
    total_sent = dict(ress)["total_sent"]
    final_balance = dict(ress)["final_balance"]
    txs = dict(ress)["txs"]
    data.append({
        'hash160': hash160,
        'address': address,
        'n_tx': n_tx,
        'total_received': total_received,
        'total_sent': total_sent,
        'final_balance': final_balance,
        'txs': txs,
    })
# =============================================================================
def get_doge(daddr):
    Dogecoin = requests.get("https://dogechain.info/api/v1/address/balance/"+ daddr)
    resedoge = Dogecoin.json()
    BalanceDoge = dict(resedoge)['balance']
    return BalanceDoge
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
def data_wallet():
    for child in range(0,20):
        bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
        bip32_child_key_obj = bip32_root_key_obj.ChildKey(
            44 + bip32utils.BIP32_HARDEN
        ).ChildKey(
            0 + bip32utils.BIP32_HARDEN
        ).ChildKey(
            0 + bip32utils.BIP32_HARDEN
        ).ChildKey(0).ChildKey(child)
        data.append({
                'bip32_root_key': bip32_root_key_obj.ExtendedKey(),
                'bip32_extended_private_key': bip32_child_key_obj.ExtendedKey(),
                'path': f"m/44'/0'/0'/0/{child}",
                'address': bip32_child_key_obj.Address(),
                'publickey': binascii.hexlify(bip32_child_key_obj.PublicKey()).decode(),
                'privatekey': bip32_child_key_obj.WalletImportFormat(),
            })
# =============================================================================            
def data_eth():
    for address_index in range(divs):
        bip44_derivation: BIP44Derivation = BIP44Derivation(
            cryptocurrency=EthereumMainnet, account=0, change=False, address=address_index
        )
        bip44_hdwallet.from_path(path=bip44_derivation)
        data.append({
                'path': bip44_hdwallet.path(),
                'address': bip44_hdwallet.address(),
                'privatekey': bip44_hdwallet.private_key(),
                'privatedec': int(bip44_hdwallet.private_key(), 16),
            })
        bip44_hdwallet.clean_derivation()
# =============================================================================
def get_rs(sig):
    rlen = int(sig[2:4], 16)
    r = sig[4:4+rlen*2]
#    slen = int(sig[6+rlen*2:8+rlen*2], 16)
    s = sig[8+rlen*2:]
    return r, s
    
def split_sig_pieces(script):
    sigLen = int(script[2:4], 16)
    sig = script[2+2:2+sigLen*2]
    r, s = get_rs(sig[4:])
    pubLen = int(script[4+sigLen*2:4+sigLen*2+2], 16)
    pub = script[4+sigLen*2+2:]
    assert(len(pub) == pubLen*2)
    return r, s, pub

# Returns list of this list [first, sig, pub, rest] for each input
def parseTx(txn):
    if len(txn) <130:
        print('[WARNING] rawtx most likely incorrect. Please check..')
        sys.exit(1)
    inp_list = []
    ver = txn[:8]
    if txn[8:12] == '0001':
        print('UnSupported Tx Input. Presence of Witness Data')
        sys.exit(1)
    inp_nu = int(txn[8:10], 16)
    
    first = txn[0:10]
    cur = 10
    for m in range(inp_nu):
        prv_out = txn[cur:cur+64]
        var0 = txn[cur+64:cur+64+8]
        cur = cur+64+8
        scriptLen = int(txn[cur:cur+2], 16)
        script = txn[cur:2+cur+2*scriptLen] #8b included
        r, s, pub = split_sig_pieces(script)
        seq = txn[2+cur+2*scriptLen:10+cur+2*scriptLen]
        inp_list.append([prv_out, var0, r, s, pub, seq])
        cur = 10+cur+2*scriptLen
    rest = txn[cur:]
    return [first, inp_list, rest]

def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 20)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: res = htmlfile.read().decode('utf-8')
    return res

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
    time.sleep(10)
    for one in range(tot):
        e = first
        for i in range(tot):
            e += inp_list[i][0] # prev_txid
            e += inp_list[i][1] # var0
            if one == i: 
                e += '1976a914' + HASH160(inp_list[one][4]) + '88ac'
            else:
                e += '00'
            e += inp_list[i][5] # seq
        e += rest + "01000000"
        z = hashlib.sha256(hashlib.sha256(bytes.fromhex(e)).digest()).hexdigest()
        res.append([inp_list[one][2], inp_list[one][3], z, inp_list[one][4], e])
    return res
#==============================================================================
def HASH160(pubk_hex):
    return hashlib.new('ripemd160', hashlib.sha256(bytes.fromhex(pubk_hex)).digest() ).hexdigest()
# =============================================================================
def SEQ_wallet():
    for i in range(0,rangediv):
        percent = div * i
        ran= start+percent
        seed = str(ran)
        HEX = "%064x" % ran
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        caddr = ice.privatekey_to_address(0, True, int(seed)) #Compressed
        uaddr = ice.privatekey_to_address(0, False, int(seed))  #Uncompressed
        p2sh = ice.privatekey_to_address(1, True, int(seed)) #p2sh
        bech32 = ice.privatekey_to_address(2, True, int(seed))  #bech32
        data.append({
            'seed': seed,
            'HEX': HEX,
            'wifc': wifc,
            'wifu': wifu,
            'caddr': caddr,
            'uaddr': uaddr,
            'p2sh': p2sh,
            'bech32': bech32,
            'percent': f"Hex scan Percent {i}%",
        })
# =============================================================================
def divsion_wallet():
    for i in range(0,rangediv):
        percent = div * i
        ran= start+percent
        seed = str(ran)
        HEX = "%064x" % ran
        divsion.append({
            'seed': seed,
            'HEX': HEX,
            'percent': f"{i}%",
        })
# =============================================================================
def iter_all(count):
    if count == 0:
        yield start
    else:
        for a in alphabet:
            if count == a:
                continue
            else:
                for scan in iter_all(count-1):
                    yield scan + a
# =============================================================================
def hash160pub(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update( sha.digest() )
    print ( "key_hash = \t" + rip.hexdigest() )
    return rip.hexdigest()
# =============================================================================
def delay_print(s):
    for c in s:
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(0.001)
# =============================================================================

# =============================================================================
prompt='''[yellow]
    ****************************** Main Menu Mizogg's Tools ***********************************
    *[/yellow]                      [green]Single Check Tools Bitcoin DOGE ETH[/green]                                [yellow]*
    *[/yellow]    Option 1.Bitcoin Address with Balance Check                    [yellow][OnLine][/yellow]     = 1      [yellow]*
    *[/yellow]    Option 2.Bitcoin Address to HASH160 Addresses starting 1,3,bc1 [yellow][OnLine][/yellow]     = 2      [yellow]*
    *[/yellow][red]    Option 3.HASH160 to Bitcoin Address (Not Working)                           = 3 [/red]     [yellow]*
    *[/yellow]    Option 4.Brain Wallet Bitcoin with Balance Check               [yellow][OnLine][/yellow]     = 4      [yellow]*
    *[/yellow]    Option 5.Hexadecimal to Decimal (HEX 2 DEC)                   [red][OffLine][/red]     = 5      [yellow]*
    *[/yellow]    Option 6.Decimal to Hexadecimal (DEC 2 HEX)                   [red][OffLine][/red]     = 6      [yellow]*
    *[/yellow]    Option 7.Hexadecimal to Address with Balance Check             [yellow][OnLine][/yellow]     = 7      [yellow]*
    *[/yellow]    Option 8.Decimal to Address with Balance Check                 [yellow][OnLine][/yellow]     = 8      [yellow]*
    *[/yellow]    Option 9.Mnemonic Words to Bitcoin Address with Balance Check  [yellow][OnLine][/yellow]     = 9      [yellow]*
    *[/yellow]    Option 10.WIF to Bitcoin Address with Balance Check            [yellow][OnLine][/yellow]     = 10     [yellow]*
    *[/yellow]    Option 11.Retrieve ECDSA signature R,S,Z rawtx or txid tool    [yellow][OnLine][/yellow]     = 11     [yellow]*
    *[/yellow]    Option 12.Range Divsion IN HEX or DEC tool                    [red][OffLine][/red]     = 12     [yellow]*
    *[/yellow]                    [green]Generators & Multi Check Tools[/green]                                       [yellow]*
    *[/yellow]    Option 13.Bitcoin Addresses from file with Balance Check       [yellow][OnLine][/yellow]     = 13     [yellow]*
    *[/yellow]    Option 14.Bitcoin Addresses from file to HASH160 file 1,3,bc1 [red][OffLine][/red]     = 14     [yellow]*
    *[/yellow]    Option 15.Brain Wallet list from file with Balance Check       [yellow][OnLine][/yellow]     = 15     [yellow]*
    *[/yellow]    Option 16.Mnemonic Words Generator Random Choice              [red][OffLine][/red]     = 16     [yellow]*
    *[/yellow]    Option 17.Bitcoin random scan randomly in Range               [red][OffLine][/red]     = 17     [yellow]*
    *[/yellow]    Option 18.Bitcoin Sequence scan sequentially in Range division[red][OffLine][/red]     = 18     [yellow]*
    *[/yellow]    Option 19.Bitcoin random Inverse K position                   [red][OffLine][/red]     = 19     [yellow]*
    *[/yellow]    Option 20.Bitcoin sequence Inverse K position                 [red][OffLine][/red]     = 20     [yellow]*
    *[/yellow]    Option 21.Bitcoin WIF Recovery or WIF Checker 5 K L           [red][OffLine][/red]     = 21     [yellow]*
    *[/yellow]    Option 22.MAGIC HEX Recovery or HEX Checker BTC ETH           [red][OffLine][/red]     = 22     [yellow]*
    *[/yellow]    Option 23.Bitcoin Addresses from file to Public Key            [yellow][OnLine][/yellow]     = 23     [yellow]*
    *[/yellow]    Option 24.Public Key from file to Bitcoin Addresses           [red][OffLine][/red]     = 24     [yellow]*
    *[/yellow]                 [green]ETH Generators & Multi Check Tools[/green]                                      [yellow]*
    *[/yellow]    Option 25.ETH Address with Balance Check&Tokens                [yellow][OnLine][/yellow]     = 25     [yellow]*
    *[/yellow]    Option 26.Mnemonic Words to dec and hex                        [yellow][OnLine][/yellow]     = 26     [yellow]*
    *[/yellow]    Option 27.Mnemonic Words Generator Random Choice              [red][OffLine][/red]     = 27     [yellow]*
    *[/yellow]    Option 28.Mnemonic Words Generator Random Choice               [yellow][OnLine][/yellow]     = 28     [yellow]*
    *[/yellow]                   [green]Extras Miscellaneous Tools[/green]                                            [yellow]*
    *[/yellow]    Option 29.Doge Coin sequential Scan Balance Check              [yellow][OnLine][/yellow]     = 29     [yellow]*
    *[/yellow]    Option 30.Doge Coin Random Scan Balance Check                  [yellow][OnLine][/yellow]     = 30     [yellow]*
    *                                                                                         *
    **************** Main Menu Mizogg's All Tools Colour Version made in Python ***************[/yellow]'''

while True:
    data = []
    mylist = []
    count=0
    skip = 0
    ammount = 0.00000000
    total= 0
    iteration = 0
    start_time = time.time()
    print(prompt)
    delay_print('Enter 1-30 : ') 
    start=int(input('TYPE HERE = '))
    if start == 1:
        print ('[green]Address Balance Check Tool[/green]')
        caddr = str(input('Enter Your Bitcoin Address Here : '))
        get_balance(caddr)
        data_info()
        for data_w in data:
            hash160 = data_w['hash160']
            address = data_w['address']
            n_tx = data_w['n_tx']
            total_received = data_w['total_received']
            total_sent = data_w['total_sent']
            final_balance = data_w['final_balance']
            print('================== Block Chain ==================')
            print('Bitcoin address   = ', address)
            print('hash160   = ', hash160)
            print('Number of tx    = ', n_tx)
            print('Total Received  = ', total_received)
            print('Total Sent      = ', total_sent)
            print('Final Balance   = ', final_balance)
            print('================== Block Chain ==================')
            time.sleep(3.0)
    elif start == 2:
        print ('[green]Address to HASH160 Tool[/green]')
        addr = str(input('Enter Your Bitcoin Address Here : '))
        if addr.startswith('1'):
            address_hash160 = (ice.address_to_h160(addr))
        if addr.startswith('3'):
            address_hash160 = (ice.address_to_h160(addr))
        if addr.startswith('bc1') and len(addr.split('\t')[0])< 50 :
            address_hash160 = (ice.bech32_address_decode(addr,coin_type=0))            
        print ('\nBitcoin Address = ', addr, '\nTo HASH160 = ', address_hash160)
        time.sleep(3.0)
    elif start == 3:
        print ('[red]HASH160 to Bitcoin Address Tool[/red]')
        hash160 =(str(input('Enter Your HASH160 Here : ')))
        print ('[red]Coming Soon not Working[/red]')
    elif start == 4:
        print ('[green]Brain Wallet Bitcoin Address Tool[/green]')    
        passphrase = (input('Type Your Passphrase HERE : '))
        wallet = BrainWallet()
        private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
        print('\nPassphrase     = ',passphrase)
        print('Private Key      = ',private_key)
        get_balance(caddr)
        data_info()
        for data_w in data:
            hash160 = data_w['hash160']
            address = data_w['address']
            n_tx = data_w['n_tx']
            total_received = data_w['total_received']
            total_sent = data_w['total_sent']
            final_balance = data_w['final_balance']
            print('================== Block Chain ==================')
            print('Bitcoin address   = ', address)
            print('hash160   = ', hash160)
            print('Number of tx    = ', n_tx)
            print('Total Received  = ', total_received)
            print('Total Sent      = ', total_sent)
            print('Final Balance   = ', final_balance)
            print('================== Block Chain ==================')
            time.sleep(3.0)
    elif start == 5:
        print('[green]Hexadecimal to Decimal Tool[/green]')
        HEX = str(input('Enter Your Hexadecimal HEX Here : '))
        dec = int(HEX, 16)
        length = len(bin(dec))
        length -=2
        print('\nHexadecimal = ',HEX, '\nTo Decimal = ', dec, '  bits ', length)
        time.sleep(3.0)
    elif start == 6:
        print('[green]Decimal to Hexadecimal Tool[/green]')
        dec = int(input('Enter Your Decimal DEC Here : '))
        HEX = "%064x" % dec
        length = len(bin(dec))
        length -=2
        print('\nDecimal = ', dec, '  bits ', length, '\nTo Hexadecimal = ', HEX)
        time.sleep(3.0)
    elif start == 7:
        prompthex= '''
    [yellow]**************************** Hexadecimal to Address Tool **********************
    *                                                                             *
    *[/yellow]    1-Single Hexadecimal to Address. Balance check [Internet required]       [yellow]*
    *[/yellow]    2-List Multi Hexadecimal to Address. Balance check [Internet required]   [yellow]*
    *[/yellow]           (Option 2 Requires hex.txt file list of Hexadecimal               [yellow]*
    *                                                                             *
    **************************** Hexadecimal to Address Tool **********************[/yellow]'''
        print(prompthex)
        delay_print('Enter 1-2 : ') 
        starthex=int(input('TYPE HERE = '))
        if starthex == 1:
            print('[green]Hexadecimal to Address Tool[/green]')
            HEX=str(input("Hexadecimal HEX ->  "))
            dec = int(HEX, 16)
            wifc = ice.btc_pvk_to_wif(HEX)
            wifu = ice.btc_pvk_to_wif(HEX, False)
            caddr = ice.privatekey_to_address(0, True, dec) #Compressed
            uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
            p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
            bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
            dogeaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, dec) #DOGE
            dogeuaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, dec) #DOGE
            ethaddr = ice.privatekey_to_ETH_address(dec)

            query = {caddr}|{uaddr}|{p2sh}|{bech32}
            request = requests.get("https://blockchain.info/multiaddr?active=" + ','.join(query), timeout=10)
            try:
                request = request.json()
                print('[yellow] HEX Entered  >> [ [/yellow]', HEX, '[yellow]][/yellow]')
                print('[yellow] DEC Returned  >> [ [/yellow]', dec, '[yellow]][/yellow]')
                print('[yellow] WIF Compressed  >> [ [/yellow]', wifc, '[yellow]][/yellow]')
                print('[yellow] WIF Uncompressed  >> [ [/yellow]', wifu, '[yellow]][/yellow]')
                get_balance(caddr)
                get_balance1(uaddr)
                get_balance2(p2sh)
                get_balance3(bech32)
                get_balance4(ethaddr)
                for row in request["addresses"]:
                    print(row)
                print('Dogecoin Address Compressed   = ', dogeaddr, '    Balance = ', get_doge(dogeaddr))
                print('Dogecoin Address UnCompressed = ', dogeuaddr, '    Balance = ', get_doge(dogeuaddr))
                time.sleep(3.0)
            except:
                pass
        if starthex == 2:
            with open("hex.txt", "r") as file:
                line_count = 0
                for line in file:
                    line != "\n"
                    line_count += 1
            with open('hex.txt', newline='', encoding='utf-8') as f:
                for line in f:
                    mylist.append(line.strip())
            for i in range(0,len(mylist)):
                myhex = mylist[i]
                HEX = myhex.split()[0]
                dec = int(HEX, 16)
                length = len(bin(dec))
                length -=2
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                dogeaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, dec) #DOGE
                dogeuaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, dec) #DOGE
                ethaddr = ice.privatekey_to_ETH_address(dec)
                balance = get_balance(caddr)
                balance1 = get_balance1(uaddr)
                balance2 = get_balance2(p2sh)
                balance3 = get_balance3(bech32)
                balance4 = get_balance4(ethaddr)
                count+=1
                total+=7
                print('Total HEX addresses Loaded:', line_count)
                if float(balance) > 0 or float(balance1) > 0 or float(balance2) > 0 or  float(balance3) > 0 or  float(balance4) > 0 or float (get_doge(dogeaddr)) > ammount or float (get_doge(dogeuaddr)) > ammount:
                    print('[yellow] HEX Entered  >> [ [/yellow]', HEX, '[yellow]][/yellow]')
                    print('[yellow] DEC Returned  >> [ [/yellow]', dec, '[yellow]][/yellow]')
                    print('[yellow] WIF Compressed  >> [ [/yellow]', wifc, '[yellow]][/yellow]')
                    print('[yellow] WIF Uncompressed  >> [ [/yellow]', wifu, '[yellow]][/yellow]')
                    get_balance(caddr)
                    get_balance1(uaddr)
                    get_balance2(p2sh)
                    get_balance3(bech32)
                    get_balance4(ethaddr)
                    print('Dogecoin Address Compressed   = ', dogeaddr, '    Balance = ', get_doge(dogeaddr))
                    print('Dogecoin Address UnCompressed = ', dogeuaddr, '    Balance = ', get_doge(dogeuaddr))
                    f=open('winner.txt','a')
                    f.write(f"  HEX Entered  >>  \n{HEX}\n DEC Returned  >>  \n{dec}  bits {length}\n\n  WIF Compressed  >>  \n{wifc}\n\n  WIF Uncompressed  >>  \n{wifu}\n\n Bitcoin Address = {caddr}  Balance  {balance}  BTC \n\n Bitcoin Address = {uaddr}  Balance  {balance1}  BTC \n\n Bitcoin Address = {p2sh}  Balance  {balance2}  BTC \n\n Bitcoin Address = {bech32} Balance  {balance3}  BTC \n\n Ethereum Address = {ethaddr}  Balance  {balance4} \n\n Dogecoin Address Compressed = {dogeaddr} \n\n       Balance  {get_doge(dogeaddr)} \n\n Dogecoin Address UnCompressed = {dogeuaddr} \n\n       Balance  {get_doge(dogeuaddr)}")
                else: 
                    print('Scan Number : ', count, ' : Total Wallets Checked : ', total)
                    get_balance(caddr)
                    get_balance1(uaddr)
                    get_balance2(p2sh)
                    get_balance3(bech32)
                    get_balance4(ethaddr)
                    print('Dogecoin Address Compressed   = ', dogeaddr, '    Balance = ', get_doge(dogeaddr))
                    print('Dogecoin Address UnCompressed = ', dogeuaddr, '    Balance = ', get_doge(dogeuaddr))
                    time.sleep(1.5)
                
    elif start == 8:
        print('[green]Decimal to Address Tool[/green]')
        delay_print('Decimal Dec (Max 115792089237316195423570985008687907852837564279074904382605163141518161494336 ) ->  ')
        dec=int(input('TYPE HERE = '))
        HEX = "%064x" % dec  
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        caddr = ice.privatekey_to_address(0, True, dec) #Compressed
        uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
        p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
        bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
        dogeaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, dec) #DOGE
        dogeuaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, dec) #DOGE
        ethaddr = ice.privatekey_to_ETH_address(dec)
        query = {caddr}|{uaddr}|{p2sh}|{bech32}
        request = requests.get("https://blockchain.info/multiaddr?active=" + ','.join(query), timeout=10)
        try:
            request = request.json()
            print('[yellow] DEC Entered  >> [ [/yellow]', dec, '[yellow]][/yellow]')
            print('[yellow] HEX Returned  >> [ [/yellow]', HEX, '[yellow]][/yellow]')
            print('[yellow] WIF Compressed  >> [ [/yellow]', wifc, '[yellow]][/yellow]')
            print('[yellow] WIF Uncompressed  >> [ [/yellow]', wifu, '[yellow]][/yellow]')
            get_balance(caddr)
            get_balance1(uaddr)
            get_balance2(p2sh)
            get_balance3(bech32)
            get_balance4(ethaddr)
            for row in request["addresses"]:
                print(row)
            print('Dogecoin Address Compressed   = ', dogeaddr, '    Balance = ', get_doge(dogeaddr))
            print('Dogecoin Address UnCompressed = ', dogeuaddr, '    Balance = ', get_doge(dogeuaddr))
            time.sleep(3.0)
        except:
            pass
    elif start == 9:
        promptword= '''
    ************************* Mnemonic Words 12/15/18/21/24 tool ************************* 
    *                                                                                    *
    *    1-OWN Words to Bitcoin with Balance Check [Internet required]                   *
    *    2-Generated Words to Bitcoin with Balance Check [Internet required]             *
    *    Type 1-2 to Start                                                               *
    *                                                                                    *
    ************************* Mnemonic Words 12/15/18/21/24 tool *************************
        '''
        print(promptword)
        delay_print('Enter 1-2 : ') 
        startwords=int(input('TYPE HERE = '))
        if startwords == 1:
            print('[green]Mnemonic 12/15/18/21/24 Words to Bitcoin Address Tool[/green]')
            wordlist = str(input('Enter Your Mnemonic Words = '))
            Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
            if Lang == 1:
                Lang1 = "english"
            elif Lang == 2:
                Lang1 = "french"
            elif Lang == 3:
                Lang1 = "italian"
            elif Lang == 4:
                Lang1 = "spanish"
            elif Lang == 5:
                Lang1 = "chinese_simplified"
            elif Lang == 6:
                Lang1 = "chinese_traditional"
            elif Lang == 7:
                Lang1 = "japanese"
            elif Lang == 8:
                Lang1 = "korean"
            else:
                print("WRONG NUMBER!!! Starting with english")
                Lang1 = "english"
            mnemo = Mnemonic(Lang1)
            mnemonic_words = wordlist
        if startwords == 2:
            print('[green]Mnemonic 12/15/18/21/24 Words to Bitcoin Address Tool[/green]')
            R = int(input('Enter Ammount Mnemonic Words 12/15/18/21/24 : '))
            if R == 12:
                s1 = 128
            elif R == 15:
                s1 = 160
            elif R == 18:
                s1 = 192
            elif R == 21:
                s1 = 224
            elif R == 24:
                s1 = 256
            else:
                print("WRONG NUMBER!!! Starting with 24 Words")
                s1 = 256
            Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
            if Lang == 1:
                Lang1 = "english"
            elif Lang == 2:
                Lang1 = "french"
            elif Lang == 3:
                Lang1 = "italian"
            elif Lang == 4:
                Lang1 = "spanish"
            elif Lang == 5:
                Lang1 = "chinese_simplified"
            elif Lang == 6:
                Lang1 = "chinese_traditional"
            elif Lang == 7:
                Lang1 = "japanese"
            elif Lang == 8:
                Lang1 = "korean"
            else:
                print("WRONG NUMBER!!! Starting with english")
                Lang1 = "english"
            mnemo = Mnemonic(Lang1)
            mnemonic_words = mnemo.generate(strength=s1)
        seed = mnemo.to_seed(mnemonic_words, passphrase="")
        data_wallet()
        for target_wallet in data:
            print('\nmnemonic_words  : ', mnemonic_words, '\nDerivation Path : ', target_wallet['path'], '\nBitcoin Address : ', target_wallet['address'], ' Balance = ', get_balance(target_wallet['address']), ' BTC', '\nPrivatekey WIF  : ', target_wallet['privatekey'])
            time.sleep(3.0)
    elif start == 10:
        print('[green]WIF to Bitcoin Address Tool[/green]')
        WIF = str(input('Enter Your Wallet Import Format WIF = '))
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
            ethaddr = ice.privatekey_to_ETH_address(dec)            
            length = len(bin(dec))
            length -=2
            print('\nDecimal = ',dec, '  bits ', length, '\n Hexadecimal = ', HEX)
            data_info()
            print('[yellow] WIF Entered  >> [ [/yellow]', WIF, '[yellow]][/yellow]')
            print('[yellow] HEX Returned  >> [ [/yellow]', HEX, '[yellow]][/yellow]')
            print('[yellow] DEC Returned  >> [ [/yellow]', dec, '[yellow]][/yellow]')
            print('[yellow] WIF Compressed  >> [ [/yellow]', wifc, '[yellow]][/yellow]')
            print('[yellow] WIF Uncompressed  >> [ [/yellow]', wifu, '[yellow]][/yellow]')
            get_balance(caddr)
            get_balance1(uaddr)
            get_balance2(p2sh)
            get_balance3(bech32)
            get_balance4(ethaddr)
            time.sleep(1.5)
            for data_w in data:
                hash160 = data_w['hash160']
                address = data_w['address']
                n_tx = data_w['n_tx']
                total_received = data_w['total_received']
                total_sent = data_w['total_sent']
                final_balance = data_w['final_balance']
                print('================== Block Chain ==================')
                print('Bitcoin address   = ', address)
                print('hash160   = ', hash160)
                print('Number of tx    = ', n_tx)
                print('Total Received  = ', total_received)
                print('Total Sent      = ', total_sent)
                print('Final Balance   = ', final_balance)
                print('================== Block Chain ==================')
                time.sleep(3.0)
            
    elif start == 11:
        promptrsz= '''[yellow]
    ************************* Retrieve ECDSA signature R,S,Z rawtx or txid tool ************************* 
    *                                                                                                   *
    *[/yellow]    1-txid  blockchain API R,S,Z calculation starts.            [yellow][OnLine]                           *
    *[/yellow]    2-rawtx R,S,Z,Pubkey for each of the inputs present in the rawtx data.     [red][OffLine][/red]           [yellow]*
    *[/yellow]    3-Adresses SoChain Transations checked blockchain API R,S,Z             [yellow][OnLine]               *
    *[/yellow]    4-txid  blockchain API R,S,Z from transaction List MORE INFORMATION         [yellow][OnLine]           [yellow]*
    *                                                                                                   *
    ************************* Retrieve ECDSA signature R,S,Z rawtx or txid tool *************************
        '''
        print(promptrsz)
        startrsz=int(input('Type 1-4 to Start   '))
        if startrsz == 1:
            txid = input(str('Type your txid here = ')) #'82e5e1689ee396c8416b94c86aed9f4fe793a0fa2fa729df4a8312a287bc2d5e'
            rawtx = ''
            if rawtx == '':
                rawtx = get_rawtx_from_blockchain(txid)
                print('\nStarting Program...')

                m = parseTx(rawtx)
                e = getSignableTxn(m)

                for i in range(len(e)):
                    print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')
                    f=open('file.txt','a')
                    f.write(f'{e[i][0]},{e[i][1]},{e[i][2]}\n')
                    f.close
        elif startrsz == 2:
            rawtx = input(str('Type your rawtx here = ')) #'01000000028370ef64eb83519fd14f9d74826059b4ce00eae33b5473629486076c5b3bf215000000008c4930460221009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9022100c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffffb0385cd9a933545628469aa1b7c151b85cc4a087760a300e855af079eacd25c5000000008b48304502210094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45022007eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffff01404b4c00000000001976a91402d8103ac969fe0b92ba04ca8007e729684031b088ac00000000'
            print('\nStarting Program...')
            m = parseTx(rawtx)
            e = getSignableTxn(m)
            for i in range(len(e)):
                print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')
                f=open('file.txt','a')
                f.write(f'{e[i][0]},{e[i][1]},{e[i][2]}\n')
                f.close
        elif startrsz == 3:
            addr = str(input('Enter Your Bitcoin Address Here : '))
            contents = requests.get('https://chain.so/api/v2/address/BTC/' + addr, timeout=10)
            res = contents.json()
            response = (contents.content)
            TXS = dict(res['data'])['txs']
            for row in TXS:
                hexs = row["txid"]
                print(hexs)
                f=open('hexs.txt','a')
                f.write(hexs + '\n')
                f.close
            mylist=[]
            header = ['Transation ID ', 'Input Index', 'R', 'K for R', 'R bits', 'S', 'K for S', 'S bits', 'Z', 'K for Z', 'Z bits','PubKey']
            fr=open('full.csv', 'a', encoding='UTF8')
            writer = csv.writer(fr)
            writer.writerow(header)
            with open('hexs.txt', newline='', encoding='utf-8') as f:
                for line in f:
                    mylist.append(line.strip())
                    print('\nStarting Program... Sleeping 10 Seconds Between Scans')
                    for x in range(0,len(mylist)):
                        txid = mylist[x]
                        rawtx = ''
                    if rawtx == '':
                        rawtx = get_rawtx_from_blockchain(txid)

                        m = parseTx(rawtx)
                        e = getSignableTxn(m)
                        for i in range(len(e)):
                            data = []
                            hex1= e[i][0]
                            r = int(hex1, 16)
                            lengthr = len(bin(r))
                            lengthr -=2
                            hex2= e[i][1]
                            s = int(hex2, 16)
                            lengths = len(bin(s))
                            lengths -=2
                            hex3= e[i][2]
                            z = int(hex3, 16)
                            lengthz = len(bin(z))
                            lengthz -=2
                            pubkey = e[i][3]
                            print ('Current Transation = ',txid)
                            print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n K for R = {r} {lengthr}  bits\n     S: {e[i][1]}\n K for S = {s} {lengths}  bits \n     Z: {e[i][2]}\n K for Z = {z} {lengthz}  bits \nPubKey: {e[i][3]}')
                            if i == 10:
                                print ('Sleep 10 Seconds Please wait Loading Next Transactions')
                                time.sleep(10)
                            f=open('filefull.txt','a')
                            f.write(f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n K for R = {r} {lengthr}  bits\n     S: {e[i][1]}\n K for S = {s} {lengths}  bits\n     Z: {e[i][2]}\n K for Z = {z} {lengthz}  bits \nPubKey: {e[i][3]}')
                            f.close
                            data = [txid, f'{i}', f'{e[i][0]}', f'{r}', f'{lengthr}', f'{e[i][1]}', f'{s}', f'{lengths}', f'{e[i][2]}', f'{z}', f'{lengthz}', f'{e[i][3]}']
                            writer.writerow(data)
        elif startrsz == 4:
            mylist = []
            data = []
            header = ['Transation ID ', 'Input Index', 'R', 'K for R', 'R bits', 'S', 'K for S', 'S bits', 'Z', 'K for Z', 'Z bits','PubKey']
            fr=open('full.csv', 'a', encoding='UTF8')
            writer = csv.writer(fr)
            writer.writerow(header)
            with open('trans.txt', newline='', encoding='utf-8') as f:
                for line in f:
                    mylist.append(line.strip())
                    print('\nStarting Program... Sleeping 10 Seconds Between Scans')
                    for x in range(0,len(mylist)):
                        txid = mylist[x]
                        rawtx = ''
                    if rawtx == '':
                        rawtx = get_rawtx_from_blockchain(txid)

                        m = parseTx(rawtx)
                        e = getSignableTxn(m)
                        for i in range(len(e)):
                            data = []
                            hex1= e[i][0]
                            r = int(hex1, 16)
                            lengthr = len(bin(r))
                            lengthr -=2
                            hex2= e[i][1]
                            s = int(hex2, 16)
                            lengths = len(bin(s))
                            lengths -=2
                            hex3= e[i][2]
                            z = int(hex3, 16)
                            lengthz = len(bin(z))
                            lengthz -=2
                            pubkey = e[i][3]
                            print ('Current Transation = ',txid)
                            print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n K for R = {r} {lengthr}  bits\n     S: {e[i][1]}\n K for S = {s} {lengths}  bits \n     Z: {e[i][2]}\n K for Z = {z} {lengthz}  bits \nPubKey: {e[i][3]}')
                            if i == 50:
                                print ('Sleep 10 Seconds Please wait Loading Next Transactions')
                                time.sleep(10)
                            f=open('filefull.txt','a')
                            f.write(f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n K for R = {r} {lengthr}  bits\n     S: {e[i][1]}\n K for S = {s} {lengths}  bits\n     Z: {e[i][2]}\n K for Z = {z} {lengthz}  bits \nPubKey: {e[i][3]}')
                            f.close
                            data = [txid, f'{i}', f'{e[i][0]}', f'{r}', f'{lengthr}', f'{e[i][1]}', f'{s}', f'{lengths}', f'{e[i][2]}', f'{z}', f'{lengthz}', f'{e[i][3]}']
                            writer.writerow(data)
        else:
            print("WRONG NUMBER!!! MUST CHOSE 1 - 4 ")

    elif start == 12:
        prompt123= '''
            ************************ Range Division Tools **************************
            *                       Divide Range in bits or bytes                  *
            *                       Option.1  Divide Range in bits  =1             *
            *                       Option.2  Divide Range in bytes =2             *
            ************************ Range Division Tools **************************
        '''
        print (prompt123)
        promptstart=int(input('Type You Choice Here Enter 1-2 :  '))
        if promptstart == 1:
            x=int(input("start range bits Min 1-255 ->  "))
            y=int(input("stop range bits Max 256 -> "))
            start=2**x
            stop=2**y
            
        elif promptstart == 2:    
            start=int(input("start range Min bytes 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
            stop=int(input("stop range Max bytes 115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))

        rangediv=int(input("Division of Range 1% t0 ???% ->  "))
        display =int(input("Choose method Display Method: 1 - HEX:; 2 - DEC  "))

        remainingtotal=stop-start
        div = round(remainingtotal / rangediv)
           
        divsion = []
               
        if display == 1:
            divsion = []
            divsion_wallet()
            for data_w in divsion:
                HEX = data_w['HEX']
                print('Percent', data_w['percent'], ' : Privatekey (hex): ', data_w['HEX'])
                time.sleep(3.0)
                with open("hex.txt", "a") as f:
                    f.write(f"""\nPercent{data_w['percent']} Privatekey (hex): {data_w['HEX']}""")
                    f.close
        elif display == 2:
            divsion = []
            divsion_wallet()
            for data_w in divsion:
                seed = data_w['seed']
                print('Percent', data_w['percent'], ' : Privatekey (dec): ', data_w['seed'])
                time.sleep(3.0)
                with open("dec.txt", "a") as f:
                    f.write(f"""\nPercent{data_w['percent']} Privatekey (dec): {data_w['seed']}""")
                    f.close
        else:
            print("WRONG NUMBER!!! MUST CHOSE 1 - 2 ")
                
    elif start == 13:
        promptchk= '''
    ************************* Bitcoin Addresses from file with Balance Check ************************* 
    *                                                                                                *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses                   *
    *    ** Your list of addresses will be check for Balance [Internet required]                     *
    *    ** ANY BITCOIN WALLETS FOUND WITH BALANCE WILL BE SAVE TO (balance.txt)                     *
    *                                                                                                *
    ************************* Bitcoin Addresses from file with Balance Check *************************
        '''
        print(promptchk)
        time.sleep(0.5)
        print('Bitcoin Addresses loading please wait..................................:')
        with open("btc.txt", "r") as file:
            line_count = 0
            for line in file:
                line != "\n"
                line_count += 1
        with open('btc.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Total Bitcoin Addresses Loaded now Checking Balance ', line_count)
        remaining=line_count
        for i in range(0,len(mylist)):
            count+=1
            remaining-=1
            caddr = mylist[i]
            balance = get_balance(caddr)
            time.sleep(0.5)
            if float(balance) > ammount:
                print(' MATCH FOUND WINNER !!!!!!!!!!!!! ')
                f=open('balance.txt','a')
                f.write('\nBitcoin Address = ' + caddr + '    Balance = ' + str(balance) + ' BTC')
                f.close()
            else:
                print ('\nScan Number = ',count, ' == Remaining = ', remaining)

    elif start == 14:
        prompthash= '''
    *********************** Bitcoin Addresses from file to HASH160 file Tool ************************* 
    *                                                                                                *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses                   *
    *    ** Your list of addresses will be converted to HASH160 [NO Internet required]               *
    *    ** HASH160 Addressess will be saved to a file called base_h160_1_bc1.txt & base_h160_3.txt  *
    *                                                                                                *
    *********************** Bitcoin Addresses from file to HASH160 file Tool *************************
        '''
        print(prompthash)
        time.sleep(0.5)
        print('Bitcoin Addresses loading please wait..................................:')
        fname = 'btc.txt'
        with open(fname) as textfile, open("base_h160_1_bc1.txt", 'w+') as f_1, open("base_h160_3.txt", 'w+') as f_2:
            for line in textfile.readlines()[1:]:
                addr = (line.rstrip('\n'))
                if addr.startswith('1'):
                    address = addr.split('\t')[0]
                    f_1.write(ice.address_to_h160(address) + '\n')
                    count +=1
                if addr.startswith('3'):
                    address = addr.split('\t')[0]
                    f_2.write(ice.address_to_h160(address) + '\n')
                    count +=1
                if addr.startswith('bc1') and len(addr.split('\t')[0])< 50 :
                    address = addr.split('\t')[0]
                    f_1.write(ice.bech32_address_decode(address,coin_type=0) + '\n')
                    count +=1
            else:
                skip += 1
                print ('Total write address>',count, '-skiped address>',skip)
 
    elif start == 15:
        promptbrain= '''
    *********************** Brain Wallet list from file with Balance Check Tool **********************
    *                                                                                                *
    *    ** This Tool needs a file called brainwords.txt with a list of Brain Wallet words           *
    *    ** Your list will be converted to Bitcoin and Balance Checked [Internet required]           *
    *    ** ANY BRAIN WALLETS FOUND WITH BALANCE WILL BE SAVE TO (winner.txt)                        *
    *                                                                                                *
    *********************** Brain Wallet list from file with Balance Check Tool **********************
        '''
        print(promptbrain)
        time.sleep(0.5)
        print('BRAIN WALLET PASSWORD LIST LOADING>>>>')
        with open("brainwords.txt", "r") as file:
            line_count = 0
            for line in file:
                line != "\n"
                line_count += 1
        with open('brainwords.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Total Brain Wallet Password Loaded:', line_count)
        remaining=line_count
        for i in range(0,len(mylist)):
            time.sleep(0.5)
            count+=1
            remaining-=1
            passphrase = mylist[i]
            wallet = BrainWallet()
            private_key, caddr = wallet.generate_address_from_passphrase(passphrase)
            balance = get_balance(caddr)
            if float(balance) > ammount:
                print(' MATCH FOUND WINNER !!!!!!!!!!!!! ')
                get_balance(caddr)
                print(' MATCH FOUND WINNER !!!!!!!!!!!!! ')
                print('Passphrase       : ',passphrase)
                print('Private Key      : ',private_key)
                print('Scan Number : ', count, ' : Remaing Passwords : ', remaining)
                f=open('winner.txt','a')
                f.write('\nBitcoin Address = ' + caddr + '    Balance = ' + str(balance) + ' BTC')
                f.write('\nPassphrase       : '+ passphrase)
                f.write('\nPrivate Key      : '+ private_key)
                f.close()
            else:
                print ('\nScan Number = ',count, ' == Remaining = ', remaining)
    elif start == 16:
        promptMnemonic= '''
    *********************** Mnemonic Words Generator Random [Offline] *****************************
    *                                                                                             *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses Database       *
    *    ** ANY MNEMONIC WORDS FOUND THAT MATCH BTC DATABASE WILL SAVE TO  (winner.txt)           *
    *                                                                                             *
    *********************** Mnemonic Words Generator Random  [Offline] ****************************
        '''
        print(promptMnemonic)
        time.sleep(0.5)
        print('Total Bitcoin Addresses Loaded ', btc_count)        
        print('Mnemonic 12/15/18/21/24 Words to Bitcoin Address Tool')
        R = int(input('Enter Ammount Mnemonic Words 12/15/18/21/24 : '))
        if R == 12:
            s1 = 128
        elif R == 15:
            s1 = 160
        elif R == 18:
            s1 = 192
        elif R == 21:
            s1 = 224
        elif R == 24:
            s1 = 256
        else:
            print("WRONG NUMBER!!! Starting with 24 Words")
            s1 = 256
        Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
        if Lang == 1:
            Lang1 = "english"
        elif Lang == 2:
            Lang1 = "french"
        elif Lang == 3:
            Lang1 = "italian"
        elif Lang == 4:
            Lang1 = "spanish"
        elif Lang == 5:
            Lang1 = "chinese_simplified"
        elif Lang == 6:
            Lang1 = "chinese_traditional"
        elif Lang == 7:
            Lang1 = "japanese"
        elif Lang == 8:
            Lang1 = "korean"
        else:
            print("WRONG NUMBER!!! Starting with english")
            Lang1 = "english"
        display = int(input('1=Full Display (Slower) 2=Slient Mode (Faster) : '))
        while True:
            data=[]
            count += 1
            total += 20
            mnemo = Mnemonic(Lang1)
            mnemonic_words = mnemo.generate(strength=s1)
            seed = mnemo.to_seed(mnemonic_words, passphrase="")
            entropy = mnemo.to_entropy(mnemonic_words)
            data_wallet()
            for target_wallet in data:
                address = target_wallet['address']
                if address in bloom_filter:
                    print('\nMatch Found')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    print('Derivation Path : ', target_wallet['path'], ' : Bitcoin Address : ', target_wallet['address'])
                    print('Privatekey WIF  : ', target_wallet['privatekey'])
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey WIF:  {target_wallet['privatekey']}
                        Public Address Bitcoin:  {target_wallet['address']}""")
            else:
                if display == 1:
                    print(' [' + str(count) + '] ------------------------')
                    print('Total Checked [' + str(total) + '] ')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    for bad_wallet in data:
                        print('Derivation Path : ', bad_wallet['path'], ' : Bitcoin Address : ', bad_wallet['address'])
                        print('Privatekey WIF  : ', bad_wallet['privatekey'])
                if display == 2:
                    print(f' {pbar.update(20)}   [ {count} ] ------Total Checked [{total}]')

    elif start == 17:
        promptrandom= '''
    *********************** Bitcoin random scan randomly in Range Tool ************************
    *                                                                                         *
    *    ** Bitcoin random scan randomly in Range [Offline]                                   *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses Database   *
    *    ** ANY MATCHING WALLETS GENERATED THAT MATCH BTC DATABASE WILL SAVE TO(winner.txt)   *
    *                                                                                         *
    **************[+] Starting.........Please Wait.....Bitcoin Address List Loading.....*******
        '''
        print(promptrandom)
        time.sleep(0.5)
        print('Total Bitcoin Addresses Loaded and Checking : ',btc_count) 
        start=int(input("start range Min 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
        stop=int(input("stop range Max 115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))
        print("Starting search... Please Wait min range: " + str(start))
        print("Max range: " + str(stop))
        print("==========================================================")
        print('Total Bitcoin Addresses Loaded and Checking : ',str (btc_count))    
        while True:
            iteration += 1
            ran=random.randrange(start,stop)
            seed = str(ran)
            HEX = "%064x" % ran   
            wifc = ice.btc_pvk_to_wif(HEX)
            wifu = ice.btc_pvk_to_wif(HEX, False)
            caddr = ice.privatekey_to_address(0, True, int(seed)) #Compressed
            uaddr = ice.privatekey_to_address(0, False, int(seed))  #Uncompressed
            P2SH = ice.privatekey_to_address(1, True, int(seed)) #p2sh
            BECH32 = ice.privatekey_to_address(2, True, int(seed))  #bech32

            if caddr in bloom_filter or uaddr in bloom_filter or P2SH in bloom_filter or BECH32 in bloom_filter :
                print('\nMatch Found')
                print('\nPrivatekey (dec): ', seed,'\nPrivatekey (hex): ', HEX, '\nPrivatekey Uncompressed: ', wifu, '\nPrivatekey compressed: ', wifc, '\nPublic Address 1 Uncompressed: ', uaddr, '\nPublic Address 1 Compressed: ', caddr, '\nPublic Address 3 P2SH: ', P2SH, '\nPublic Address bc1 BECH32: ', BECH32)
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + seed)
                f.write('\nPrivatekey (hex): ' + HEX)
                f.write('\nPrivatekey Uncompressed: ' + wifu)
                f.write('\nPrivatekey compressed: ' + wifc)
                f.write('\nPublic Address 1 Compressed: ' + caddr)
                f.write('\nPublic Address 1 Uncompressed: ' + uaddr)
                f.write('\nPublic Address 3 P2SH: ' + P2SH)
                f.write('\nPublic Address bc1 BECH32: ' + BECH32)
            else:
                if iteration % 10000 == 0:
                    print(f' {pbar.update(40000)} ---HEX [{HEX}]')
    elif start == 18:
        promptsequence= '''
    *********************** Bitcoin sequence Divison in Range Tool ************************
    *                                                                                         *
    *    ** Bitcoin sequence & Range Divison by 1%-1000000%                                   *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses Database   *
    *    ** ANY MATCHING WALLETS GENERATED THAT MATCH BTC DATABASE WILL SAVE TO(winner.txt)   *
    *                                                                                         *
    **************[+] Starting.........Please Wait.....Bitcoin Address List Loading.....*******
        '''
        print(promptsequence)
        time.sleep(0.5)
        print('Total Bitcoin Addresses Loaded and Checking : ',btc_count) 
        start=int(input("start range Min 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
        stop=int(input("stop range Max 115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))
        mag=int(input("Magnitude Jump Stride -> "))
        rangediv=int(input("Division of Range 1% t0 ???% ->  "))
        display =int(input("Choose method Display Method: 1 - Less Details:(Fastest); 2 - Hex Details:(Slower); 3 - Wallet Details:(Slower)  "))
        print("Starting search... Please Wait min range: " + str(start))
        print("Max range: " + str(stop))
        print('Total Bitcoin Addresses Loaded and Checking : ',btc_count)

        remainingtotal=stop-start
        div = round(remainingtotal / rangediv)
        finish = div + start
        finishscan = round(stop / rangediv)
        while start < finish:
            try:
                data = []
                remainingtotal-=mag
                finish-=mag
                start+=mag
                count += 1
                total += rangediv*4
                SEQ_wallet()
                for data_w in data:
                    caddr = data_w['caddr']
                    uaddr = data_w['uaddr']
                    p2sh = data_w['p2sh']
                    bech32 = data_w['bech32']
                    if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter:
                        print('\nMatch Found IN : ', data_w['percent'])
                        print('\nPrivatekey (dec): ', data_w['seed'], '\nPrivatekey (hex): ', data_w['HEX'], '\nPrivatekey Uncompressed: ', data_w['wifu'], '\nPrivatekey compressed: ', data_w['wifc'], '\nPublic Address 1 Uncompressed: ', data_w['uaddr'], '\nPublic Address 1 compressed: ', data_w['caddr'], '\nPublic Address 3 P2SH: ', data_w['p2sh'], '\nPublic Address bc1 BECH32: ', data_w['bech32'])
                        with open("winner.txt", "a") as f:
                            f.write(f"""\nMatch Found IN  {data_w['percent']}
                            Privatekey (dec):  {data_w['seed']}
                            Privatekey (hex): {data_w['HEX']}
                            Privatekey Uncompressed:  {data_w['wifu']}
                            Privatekey Compressed:  {data_w['wifc']}
                            Public Address 1 Uncompressed:  {data_w['uaddr']}
                            Public Address 1 Compressed:  {data_w['caddr']}
                            Public Address 3 P2SH:  {data_w['p2sh']}
                            Public Address bc1 BECH32:  {data_w['bech32']}""")
                            
                    else:
                        if display == 1:
                            print('Scan: ', count , ' :Remaining: ', str(finish), ' :Total: ', str(total), end='\r')
                        elif display == 2:
                            print(data_w['percent'], '\nPrivatekey (hex): ', data_w['HEX'], end='\r')
                        elif display == 3:
                            print(data_w['percent'])
                            print('\nPrivatekey (dec): ', data_w['seed'], '\nPrivatekey (hex): ', data_w['HEX'], '\nPrivatekey Uncompressed: ', data_w['wifu'], '\nPrivatekey compressed: ', data_w['wifc'], '\nPublic Address 1 Uncompressed: ', data_w['uaddr'], '\nPublic Address 1 compressed: ', data_w['caddr'], '\nPublic Address 3 P2SH: ', data_w['p2sh'], '\nPublic Address bc1 BECH32: ', data_w['bech32'])
                        else:
                            print("WRONG NUMBER!!! MUST CHOSE 1, 2 or 3")
                            break
                        
                                
            except(KeyboardInterrupt, SystemExit):
                exit('\nCTRL-C detected. Exiting gracefully.  Thank you and Happy Hunting')
    
    elif start == 19:
        promptinverse= '''
    *********************** Bitcoin Random Inverse K Range Tool *******************************
    *                                                                                         *
    *    ** Bitcoin Random Inverse K Range                                                    *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses Database   *
    *    ** ANY MATCHING WALLETS GENERATED THAT MATCH BTC DATABASE WILL SAVE TO(winner.txt)   *
    *                                                                                         *
    **************[+] Starting.........Please Wait.....Bitcoin Address List Loading.....*******
        '''
        print(promptinverse)
        time.sleep(0.5)
        print('Total Bitcoin Addresses Loaded and Checking : ',btc_count)  
        start = int(input("start range Min 1-57896044618658097711785492504343953926418782139537452191302581570759080747168 ->  "))
        stop = int(input("stop range MAX 57896044618658097711785492504343953926418782139537452191302581570759080747169 ->  "))
        print("Starting search... Please Wait min range: " + str(start))
        print("Max range: " + str(stop))
        print("==========================================================")
        print('Total Bitcoin Addresses Loaded and Checking : ',btc_count)
        while True:
            iteration += 1
            ran=random.randrange(start,stop)
            k1 = int(ran)
            HEXk1 = "%064x" % k1
            k2 = (k1*(n-1))%n
            HEXk2 = "%064x" % k2
            wifck1 = ice.btc_pvk_to_wif(HEXk1)
            wifuk1 = ice.btc_pvk_to_wif(HEXk1, False)
            caddrk1 = ice.privatekey_to_address(0, True, k1) #Compressed
            uaddrk1 = ice.privatekey_to_address(0, False, k1)  #Uncompressed
            P2SHk1 = ice.privatekey_to_address(1, True, k1) #p2sh
            BECH32k1 = ice.privatekey_to_address(2, True, k1)  #bech32
            
            wifck2 = ice.btc_pvk_to_wif(HEXk2)
            wifuk2 = ice.btc_pvk_to_wif(HEXk2, False)
            caddrk2 = ice.privatekey_to_address(0, True, k2) #Compressed
            uaddrk2 = ice.privatekey_to_address(0, False, k2)  #Uncompressed
            P2SHk2 = ice.privatekey_to_address(1, True, k2) #p2sh
            BECH32k2 = ice.privatekey_to_address(2, True, k2)  #bech32    
            if caddrk1 in bloom_filter or uaddrk1 in bloom_filter or P2SHk1 in bloom_filter or BECH32k1 in bloom_filter :
                print('\nMatch Found')
                print('\nPrivatekey (dec): ', k1,'\nPrivatekey (hex): ', HEXk1, '\nPrivatekey Uncompressed: ', wifuk1, '\nPrivatekey compressed: ', wifck1, '\nPublic Address 1 Uncompressed: ', uaddrk1, '\nPublic Address 1 Compressed: ', caddrk1, '\nPublic Address 3 P2SH: ', P2SHk1, '\nPublic Address bc1 BECH32: ', BECH32k1)
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(k1))
                f.write('\nPrivatekey (hex): ' + HEXk1)
                f.write('\nPrivatekey Uncompressed: ' + wifuk1)
                f.write('\nPrivatekey compressed: ' + wifck1)
                f.write('\nPublic Address 1 Compressed: ' + caddrk1)
                f.write('\nPublic Address 1 Uncompressed: ' + uaddrk1)
                f.write('\nPublic Address 3 P2SH: ' + P2SHk1)
                f.write('\nPublic Address bc1 BECH32: ' + BECH32k1)
            if caddrk2 in bloom_filter or uaddrk2 in bloom_filter or P2SHk2 in bloom_filter or BECH32k2 in bloom_filter :
                print('\nMatch Found')
                print('\nPrivatekey (dec): ', k2,'\nPrivatekey (hex): ', HEXk2, '\nPrivatekey Uncompressed: ', wifuk2, '\nPrivatekey compressed: ', wifck2, '\nPublic Address 1 Uncompressed: ', uaddrk2, '\nPublic Address 1 Compressed: ', caddrk2, '\nPublic Address 3 P2SH: ', P2SHk2, '\nPublic Address bc1 BECH32: ', BECH32k2)
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(k2))
                f.write('\nPrivatekey (hex): ' + HEXk2)
                f.write('\nPrivatekey Uncompressed: ' + wifuk2)
                f.write('\nPrivatekey compressed: ' + wifck2)
                f.write('\nPublic Address 1 Compressed: ' + caddrk2)
                f.write('\nPublic Address 1 Uncompressed: ' + uaddrk2)
                f.write('\nPublic Address 3 P2SH: ' + P2SHk2)
                f.write('\nPublic Address bc1 BECH32: ' + BECH32k2)
            else:
                if iteration % 10000 == 0:
                    print(f' {pbar.update(80000)} ---HEX [{HEXk1}]')
    elif start == 20:
        promptinversesq= '''
    *********************** Bitcoin sequence Inverse K Range Tool *****************************
    *                                                                                         *
    *    ** Bitcoin sequence Inverse K Range                                                  *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses Database   *
    *    ** ANY MATCHING WALLETS GENERATED THAT MATCH BTC DATABASE WILL SAVE TO(winner.txt)   *
    *                                                                                         *
    **************[+] Starting.........Please Wait.....Bitcoin Address List Loading.....*******
        '''
        print(promptinversesq)
        time.sleep(0.5)
        print('Total Bitcoin Addresses Loaded and Checking : ', btc_count)  
        start = int(input("start range Min 1-57896044618658097711785492504343953926418782139537452191302581570759080747168 ->  "))
        stop = int(input("stop range MAX 57896044618658097711785492504343953926418782139537452191302581570759080747169 ->  "))
        mag=int(input("Magnitude Jump Stride -> "))
        print("Starting search... Please Wait min range: " + str(start))
        print("Max range: " + str(stop))
        print("==========================================================")
        print('Total Bitcoin Addresses Loaded and Checking : ', btc_count)
        while start < stop:
            iteration += 1
            start+=mag
            k1 = int(start)
            elapsed = time.time() - start_time
            HEXk1 = "%064x" % k1
            k2 = (k1*(n-1))%n
            HEXk2 = "%064x" % k2
            wifck1 = ice.btc_pvk_to_wif(HEXk1)
            wifuk1 = ice.btc_pvk_to_wif(HEXk1, False)
            caddrk1 = ice.privatekey_to_address(0, True, k1) #Compressed
            uaddrk1 = ice.privatekey_to_address(0, False, k1)  #Uncompressed
            P2SHk1 = ice.privatekey_to_address(1, True, k1) #p2sh
            BECH32k1 = ice.privatekey_to_address(2, True, k1)  #bech32
            
            wifck2 = ice.btc_pvk_to_wif(HEXk2)
            wifuk2 = ice.btc_pvk_to_wif(HEXk2, False)
            caddrk2 = ice.privatekey_to_address(0, True, k2) #Compressed
            uaddrk2 = ice.privatekey_to_address(0, False, k2)  #Uncompressed
            P2SHk2 = ice.privatekey_to_address(1, True, k2) #p2sh
            BECH32k2 = ice.privatekey_to_address(2, True, k2)  #bech32    
            if caddrk1 in bloom_filter or uaddrk1 in bloom_filter or P2SHk1 in bloom_filter or BECH32k1 in bloom_filter :
                print('\nMatch Found')
                print('\nPrivatekey (dec): ', k1,'\nPrivatekey (hex): ', HEXk1, '\nPrivatekey Uncompressed: ', wifuk1, '\nPrivatekey compressed: ', wifck1, '\nPublic Address 1 Uncompressed: ', uaddrk1, '\nPublic Address 1 Compressed: ', caddrk1, '\nPublic Address 3 P2SH: ', P2SHk1, '\nPublic Address bc1 BECH32: ', BECH32k1)
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(k1))
                f.write('\nPrivatekey (hex): ' + HEXk1)
                f.write('\nPrivatekey Uncompressed: ' + wifuk1)
                f.write('\nPrivatekey compressed: ' + wifck1)
                f.write('\nPublic Address 1 Compressed: ' + caddrk1)
                f.write('\nPublic Address 1 Uncompressed: ' + uaddrk1)
                f.write('\nPublic Address 3 P2SH: ' + P2SHk1)
                f.write('\nPublic Address bc1 BECH32: ' + BECH32k1)
            if caddrk2 in bloom_filter or uaddrk2 in bloom_filter or P2SHk2 in bloom_filter or BECH32k2 in bloom_filter :
                print('\nMatch Found')
                print('\nPrivatekey (dec): ', k2,'\nPrivatekey (hex): ', HEXk2, '\nPrivatekey Uncompressed: ', wifuk2, '\nPrivatekey compressed: ', wifck2, '\nPublic Address 1 Uncompressed: ', uaddrk2, '\nPublic Address 1 Compressed: ', caddrk2, '\nPublic Address 3 P2SH: ', P2SHk2, '\nPublic Address bc1 BECH32: ', BECH32k2)
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(k2))
                f.write('\nPrivatekey (hex): ' + HEXk2)
                f.write('\nPrivatekey Uncompressed: ' + wifuk2)
                f.write('\nPrivatekey compressed: ' + wifck2)
                f.write('\nPublic Address 1 Compressed: ' + caddrk2)
                f.write('\nPublic Address 1 Uncompressed: ' + uaddrk2)
                f.write('\nPublic Address 3 P2SH: ' + P2SHk2)
                f.write('\nPublic Address bc1 BECH32: ' + BECH32k2)
            else:
                if iteration % 10000 == 0:
                    print(f' {pbar.update(80000)} ---HEX [{HEXk1}]')
        
    elif start == 21:
        promptWIF= '''
    *********************** Bitcoin WIF Recovery or WIF Checker Tool **************************
    *                                                                                         *
    *    ** Find the Missing parts of a Wallet Import format(WIF) for Bitcoin                 *
    *    ** This Tool only works with WIF's Starting  5 K L                                   *
    *    ** ANY MATCHING WIF's GENERATED THAT MATCH ADDRESS WILL SAVE TO(winner.txt)          *
    *                                                                                         *
    *********************** Bitcoin WIF Recovery or WIF Checker Tool **************************
        '''
        print(promptWIF)
        time.sleep(0.5)
        miss = int(input('How Many Missing Chars Enter 0 for none : '))
        if miss == 0:
            startsingle= str(input('Enter Your WIF HERE : '))
            if startsingle[0] == '5':
                private_key_WIF = startsingle
                first_encode = base58.b58decode(private_key_WIF)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
            if startsingle[0] in ['L', 'K']:
                private_key_WIF = startsingle
                first_encode = base58.b58decode(private_key_WIF)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-10]
            key = Key.from_hex(str(private_key.decode('utf-8')))
            wif = bytes_to_wif(key.to_bytes(), compressed=False)
            wif1 = bytes_to_wif(key.to_bytes(), compressed=True)
            key1 = Key(wif)
            addr = key.address
            addr1 = key1.address
            print('\nPrivateKey= ', private_key.decode('utf-8'), '\nCompressed Address = ', addr, '\nCompressed WIF = ', wif1, '\nUncompressed = ', addr1, '\nUncompressed WIF = ', wif)
            f=open('winner.txt','a')
            f.write('\nPrivateKey= ' + private_key.decode('utf-8') + '\nCompressed Address = ' + addr + '\nCompressed WIF = ' + wif1 + '\nUncompressed = ' + addr1 + '\nUncompressed WIF = ' + wif)
            f.close()
        else:
            start= str(input('Leave Bank or Input Starting Part : '))
            stop = str(input('Leave Bank or Input Ending Part : '))
            add= str(input('Enter Bitcoin address Looking to match WIF = '))
            for a in iter_all(miss):
                total+=1
                if start[0] == '5':
                    private_key_WIF = a + stop
                    first_encode = base58.b58decode(private_key_WIF)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-8]
                if start[0] in ['L', 'K']:
                    private_key_WIF = a + stop
                    first_encode = base58.b58decode(private_key_WIF)
                    private_key_full = binascii.hexlify(first_encode)
                    private_key = private_key_full[2:-10]
                key = Key.from_hex(str(private_key.decode('utf-8')))
                wif = bytes_to_wif(key.to_bytes(), compressed=False)
                wif1 = bytes_to_wif(key.to_bytes(), compressed=True)
                key1 = Key(wif)
                addr = key.address
                addr1 = key1.address
                print(' Scanning : ', total,' : Current TEST WIF= ', private_key_WIF, end='\r')
                #print('\n GOOD LUCK AND HAPPY HUNTING', '\nPrivateKey= ', private_key.decode('utf-8'), '\nCompressed Address = ', addr, '\nCompressed WIF = ', wif1, '\nUncompressed = ', addr1, '\nUncompressed WIF = ', wif)
                if addr in add or addr1 in add:
                    print('\n Congraz FOUND!!!', '\nPrivateKey= ', private_key.decode('utf-8'), '\nCompressed Address = ', addr, '\nCompressed WIF = ', wif1, '\nUncompressed = ', addr1, '\nUncompressed WIF = ', wif)
                    f=open('winner.txt','a')
                    f.write('\n Congraz FOUND!!!' + '\nPrivateKey= ' + private_key.decode('utf-8') + '\nCompressed Address = ' + addr + '\nCompressed WIF = ' + wif1 + '\nUncompressed = ' + addr1 + '\nUncompressed WIF = ' + wif)
                    f.close()
    elif start == 22:
        promptHEX= f'''[yellow]
    *********************** Bitcoin ETH Recovery HEX Checker Tool **************************
    *                                                                                      *
    *[/yellow]    ** Find the Missing parts from (HEX) for Bitcoin or ETH                           [yellow]*
    *[/yellow]    ** ANY MATCHING HEX's GENERATED THAT MATCH ADDRESS WILL SAVE TO [yellow](winner.txt)[/yellow]      [yellow]*
    *[/yellow]                    Total addresses LOADED    {addr_count}                                [yellow]*
    *                                                                                      *
    *********************** Bitcoin ETH Recovery HEX Checker Tool **************************[/yellow]
        '''
        print(promptHEX)
        time.sleep(0.5)
        promptlist=('''[yellow]
    *********************************************************
    *                                                       *
    *[/yellow]    Option 1.RANDOM [yellow](EDIT C1 - C64 MAGIC)[/yellow]       =  1   [yellow]*
    *[/yellow]    Option 2.FIND START Mising amount FORWARD   =  2   [yellow]*
    *[/yellow]    Option 3.FIND END Mising amount   FORWARD   =  3   [yellow]*
    *[/yellow]    Option 4.FIND START Mising amount BACKWARD  =  4   [yellow]*
    *[/yellow]    Option 5.FIND END Mising amount   BACKWARD  =  5   [yellow]*
    *             [yellow]PICK OPTION 1-5 TO BEGIN [/yellow]                 *
    *********************************************************[/yellow] ''')
        print(promptlist)        
        starting=int(input('TYPE HERE =   '))

        if starting == 1:
            promptdiplay=('''[yellow]
            **********[/yellow] DISPLAY [yellow]********
            *[/yellow]  1 . FAST  (HEX)        [yellow]*
            *[/yellow]  2 . Mid   HEX&DEC      [yellow]*
            *[/yellow]  3 . SLOW  Full Display [yellow]*
            **********[/yellow] DISPLAY [yellow]********[/yellow]
            
         Enter Your Choice 1-3 ''')
            print(promptdiplay)
            startprint=int(input('TYPE HERE =   ')) 
            while True:
                c1 = '0' #random.choice('0123456789abcdef')
                c2 = '0' #random.choice('0123456789abcdef')
                c3 = '0' #random.choice('0123456789abcdef')
                c4 = random.choice('0123456789abcdef')
                c5 = random.choice('0123456789abcdef')
                c6 = random.choice('0123456789abcdef')
                c7 = random.choice('0123456789abcdef')
                c8 = random.choice('0123456789abcdef')
                c9 = random.choice('0123456789abcdef')
                c10 = random.choice('0123456789abcdef')
                c11 = random.choice('0123456789abcdef')
                c12 = random.choice('0123456789abcdef')
                c13 = random.choice('0123456789abcdef')
                c14 = random.choice('0123456789abcdef')
                c15 = random.choice('0123456789abcdef')
                c16 = random.choice('0123456789abcdef')
                c17 = random.choice('0123456789abcdef')
                c18 = random.choice('0123456789abcdef')
                c19 = random.choice('0123456789abcdef')
                c20 = random.choice('0123456789abcdef')
                c21 = random.choice('0123456789abcdef')
                c22 = random.choice('0123456789abcdef')
                c23 = random.choice('0123456789abcdef')
                c24 = random.choice('0123456789abcdef')
                c25 = random.choice('0123456789abcdef')
                c26 = random.choice('0123456789abcdef')
                c27 = random.choice('0123456789abcdef')
                c28 = random.choice('0123456789abcdef')
                c29 = random.choice('0123456789abcdef')
                c30 = random.choice('0123456789abcdef')
                c31 = random.choice('0123456789abcdef')
                c32 = random.choice('0123456789abcdef')
                c33 = random.choice('0123456789abcdef')
                c34 = random.choice('0123456789abcdef')
                c35 = random.choice('0123456789abcdef')
                c36 = random.choice('0123456789abcdef')
                c37 = random.choice('0123456789abcdef')
                c38 = random.choice('0123456789abcdef')
                c39 = random.choice('0123456789abcdef')
                c40 = random.choice('0123456789abcdef')
                c41 = random.choice('0123456789abcdef')
                c42 = random.choice('0123456789abcdef')
                c43 = random.choice('0123456789abcdef')
                c44 = random.choice('0123456789abcdef')
                c45 = random.choice('0123456789abcdef')
                c46 = random.choice('0123456789abcdef')
                c47 = random.choice('0123456789abcdef')
                c48 = random.choice('0123456789abcdef')
                c49 = random.choice('0123456789abcdef')
                c50 = random.choice('0123456789abcdef')
                c51 = random.choice('0123456789abcdef')
                c52 = random.choice('0123456789abcdef')
                c53 = random.choice('0123456789abcdef')
                c54 = random.choice('0123456789abcdef')
                c55 = random.choice('0123456789abcdef')
                c56 = random.choice('0123456789abcdef')
                c57 = random.choice('0123456789abcdef')
                c58 = random.choice('0123456789abcdef')
                c59 = random.choice('0123456789abcdef')
                c60 = random.choice('0123456789abcdef')
                c61 = random.choice('0123456789abcdef')
                c62 = random.choice('0123456789abcdef')
                c63 = random.choice('0123456789abcdef')
                c64 = random.choice('0123456789abcdef')
                magic = (c1+c2+c3+c4+c5+c6+c7+c8+c9+c10+c11+c12+c13+c14+c15+c16+c17+c18+c19+c20+c21+c22+c23+c24+c25+c26+c27+c28+c29+c30+c31+c32+c33+c34+c35+c36+c37+c38+c39+c40+c41+c42+c43+c44+c45+c46+c47+c48+c49+c50+c51+c52+c53+c54+c55+c56+c57+c58+c59+c60+c61+c62+c63+c64)
                HEX = str(magic)
                dec = int(HEX, 16)
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                ethaddr = ice.privatekey_to_ETH_address(dec)
                length = len(bin(dec))
                length -=2
                if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print_data_plain()
                    save_data_plain()
                else:
                    if startprint == 1:
                        print(HEX, end='\r')
                    if startprint == 2:
                        print(HEX, ' : ', dec, ' : ', length, ' Bits', end='\r')
                    if startprint == 3:
                        print_data_plain()
                
                
        if starting == 2:
            prompt123=('''[yellow]
            **************[/yellow] hex_add Menu Version 1 Offline[yellow]****
            *[/yellow]                   FORWARD                     [yellow]*
            *[/yellow]    Ammount of HEX Missing from START          [yellow]*
            *[/yellow]                   FORWARD                     [yellow]*
            **************[/yellow] hex_add Menu Version 1 [yellow]***********[/yellow]
            
         Enter Your Choice 1-63 ''')
            print(prompt123)
            startscan=int(input('TYPE HERE =   ')) 
            removenum =str(input("Known END HEX ->  "))
            
            promptdiplay=('''[yellow]
            **********[/yellow] DISPLAY [yellow]********
            *[/yellow]  1 . FAST  (HEX)        [yellow]*
            *[/yellow]  2 . Mid   HEX&DEC      [yellow]*
            *[/yellow]  3 . SLOW  Full Display [yellow]*
            **********[/yellow] DISPLAY [yellow]********[/yellow]
            
         Enter Your Choice 1-3 ''')
            print(promptdiplay)
            startprint=int(input('TYPE HERE =   ')) 
            for HEXIN in iter_all_front(startscan):
                HEX = HEXIN + str(removenum)
                dec = int(HEX, 16)
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                ethaddr = ice.privatekey_to_ETH_address(dec)
                length = len(bin(dec))
                length -=2
                if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print_data_plain()
                    save_data_plain()
                else:
                    if startprint == 1:
                        print(HEX, end='\r')
                    if startprint == 2:
                        print(HEX, ' : ', dec, ' : ', length, ' Bits', end='\r')
                    if startprint == 3:
                        print_data_plain()
                
        if starting == 3:
            prompt123= ('''[yellow]
            **************[/yellow] hex_add Menu Version 1 Offline[yellow]****
            *[/yellow]                   FORWARD                     [yellow]*
            *[/yellow]    Ammount of HEX Missing from END            [yellow]*
            *[/yellow]                   FORWARD                     [yellow]*
            **************[/yellow] hex_add Menu Version 1 [yellow]***********[/yellow]
            
         Enter Your Choice 1-63 ''')  
            print(prompt123)
            startscan=int(input('TYPE HERE =   '))
            removenum =str(input("Known HEX START ->  "))
            promptdiplay=('''[yellow]
            **********[/yellow] DISPLAY [yellow]********
            *[/yellow]  1 . FAST  (HEX)        [yellow]*
            *[/yellow]  2 . Mid   HEX&DEC      [yellow]*
            *[/yellow]  3 . SLOW  Full Display [yellow]*
            **********[/yellow] DISPLAY [yellow]********[/yellow]
            
         Enter Your Choice 1-3 ''')
            print(promptdiplay)
            startprint=int(input('TYPE HERE =   ')) 
            for HEXIN in iter_all_front(startscan):
                HEX = str(removenum) + HEXIN
                dec = int(HEX, 16)
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                ethaddr = ice.privatekey_to_ETH_address(dec)
                length = len(bin(dec))
                length -=2
                if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('PrivateKey (hex) : ', HEX)
                    print('PrivateKey (dec) : ', dec)
                    print('PrivateKey (wif) Compressed   : ', wifc)
                    print('PrivateKey (wif) UnCompressed : ', wifu)
                    print('Bitcoin Address Compressed   = ', caddr)
                    print('Bitcoin Address UnCompressed = ', uaddr)
                    print('Bitcoin Address p2sh         = ', p2sh)
                    print('Bitcoin Address Bc1  bech32  = ', bech32)
                    print('ETH Address = ', ethaddr)
                    save_data_plain()
                else:
                    if startprint == 1:
                        print(HEX, end='\r')
                    if startprint == 2:
                        print(HEX, ' : ', dec, ' : ', length, ' Bits', end='\r')
                    if startprint == 3:
                        print_data_plain()

        if starting == 4:
            prompt123= ('''[yellow]
            **************[/yellow] hex_add Menu Version 1 Offline[yellow]****
            *[/yellow]                  BACKWARD                     [yellow]*
            *[/yellow]    Ammount of HEX Missing from START          [yellow]*
            *[/yellow]                  BACKWARD                     [yellow]*
            **************[/yellow] hex_add Menu Version 1 [yellow]***********[/yellow]
            
         Enter Your Choice 1-63 ''')
            print(prompt123)
            startscan=int(input('TYPE HERE =   ')) 
            removenum =str(input("Known END HEX ->  "))
            promptdiplay=('''[yellow]
            **********[/yellow] DISPLAY [yellow]********
            *[/yellow]  1 . FAST  (HEX)        [yellow]*
            *[/yellow]  2 . Mid   HEX&DEC      [yellow]*
            *[/yellow]  3 . SLOW  Full Display [yellow]*
            **********[/yellow] DISPLAY [yellow]********[/yellow]
            
         Enter Your Choice 1-3 ''')
            print(promptdiplay)
            startprint=int(input('TYPE HERE =   ')) 
            for HEXIN in iter_all_back(startscan):
                HEX = HEXIN + str(removenum)
                dec = int(HEX, 16)
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                ethaddr = ice.privatekey_to_ETH_address(dec)
                length = len(bin(dec))
                length -=2
                if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print_data_plain()
                    save_data_plain()
                else:
                    if startprint == 1:
                        print(HEX, end='\r')
                    if startprint == 2:
                        print(HEX, ' : ', dec, ' : ', length, ' Bits', end='\r')
                    if startprint == 3:
                        print_data_plain()
                
        if starting == 5:
            prompt123= ('''[yellow]
            **************[/yellow] hex_add Menu Version 1 Offline[yellow]****
            *[/yellow]                  BACKWARD                     [yellow]*
            *[/yellow]    Ammount of HEX Missing from END            [yellow]*
            *[/yellow]                  BACKWARD                     [yellow]*
            **************[/yellow] hex_add Menu Version 1 [yellow]***********[/yellow]
            
         Enter Your Choice 1-63 ''')  
            print(prompt123)
            startscan=int(input('TYPE HERE =   '))
            removenum =str(input("Known HEX START ->  "))
            promptdiplay=('''[yellow]
            **********[/yellow] DISPLAY [yellow]********
            *[/yellow]  1 . FAST  (HEX)        [yellow]*
            *[/yellow]  2 . Mid   HEX&DEC      [yellow]*
            *[/yellow]  3 . SLOW  Full Display [yellow]*
            **********[/yellow] DISPLAY [yellow]********[/yellow]
            
         Enter Your Choice 1-3 ''')
            print(promptdiplay)
            startprint=int(input('TYPE HERE =   ')) 
            for HEXIN in iter_all_back(startscan):
                HEX = str(removenum) + HEXIN
                dec = int(HEX, 16)
                wifc = ice.btc_pvk_to_wif(HEX)
                wifu = ice.btc_pvk_to_wif(HEX, False)
                caddr = ice.privatekey_to_address(0, True, dec) #Compressed
                uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
                p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
                bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
                ethaddr = ice.privatekey_to_ETH_address(dec)
                length = len(bin(dec))
                length -=2
                if caddr in bloom_filter or uaddr in bloom_filter or p2sh in bloom_filter or bech32 in bloom_filter or ethaddr in bloom_filter1:
                    print('PrivateKey (hex) : ', HEX)
                    print('PrivateKey (dec) : ', dec)
                    print('PrivateKey (wif) Compressed   : ', wifc)
                    print('PrivateKey (wif) UnCompressed : ', wifu)
                    print('Bitcoin Address Compressed   = ', caddr)
                    print('Bitcoin Address UnCompressed = ', uaddr)
                    print('Bitcoin Address p2sh         = ', p2sh)
                    print('Bitcoin Address Bc1  bech32  = ', bech32)
                    print('ETH Address = ', ethaddr)
                    save_data_plain()
                else:
                    if startprint == 1:
                        print(HEX, end='\r')
                    if startprint == 2:
                        print(HEX, ' : ', dec, ' : ', length, ' Bits', end='\r')
                    if startprint == 3:
                        print_data_plain()
                        
    elif start == 23:
        promptPUB= '''
    *********************** Bitcoin Addresses from file to Public Key Tool ********************
    *                                                                                         *
    *    ** This Tool needs a file called btc.txt with a list of Bitcoin Addresses            *
    *    ** Your list of addresses will be check for Known Public keys [Internet required]    *
    *    ** ANY BITCOIN ADDRESS WITH A PUBLIC KEY WILL BE SAVE TO (pubkeys.txt)               *
    *                                                                                         *
    *********************** Bitcoin Addresses from file to Public Key Tool ********************
        '''
        print(promptPUB)
        time.sleep(0.5)
        print('Bitcoin Addresses loading to check for public keys please wait ................:')
        with open('btc.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Bitcoin Addresses Loaded now Checking for Public Keys ')
        myfile = open('pubkeys.txt', 'w')

        for i in range(0,len(mylist)):
            address = mylist[i]
            link = f"https://blockchain.info/q/pubkeyaddr/{address}"
            time.sleep(0.5)
            f = requests.get(link)
            if(f.text == ''):
                pass
            else:
                myfile.write("%s\n" % f.text)
                print(f.text)

        myfile.close()
    
    elif start == 24:
        promptADD2PUB= '''
    *********************** Public Key from file to Bitcoin Addresses Tool ********************
    *                                                                                         *
    *    ** This Tool needs a file called pubkeys.txt with a list of Public Keys              *
    *    ** Your list of Public Keys will be Coverted to Bitcion Addresses  [OFF Line]        *
    *    ** All THE PUBLIC KEY INFORMATION WILL BE SAVE TO (add_info.txt)                     *
    *                                                                                         *
    *********************** Public Key from file to Bitcoin Addresses Tool ********************
        '''
        print(promptADD2PUB)
        time.sleep(0.5)
        print('public keys Loading to Bitcion Addresses please wait ................:')
        import hashlib, base58
        with open('pubkeys.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())

        for i in range(0,len(mylist)):
            pubkey = mylist[i]
            compress_pubkey = False
            if (compress_pubkey):
                if (ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0):
                    pubkey_compressed = '02'
                else:
                    pubkey_compressed = '03'
                pubkey_compressed += pubkey[2:66]
                hex_str = bytearray.fromhex(pubkey_compressed)
            else:
                hex_str = bytearray.fromhex(pubkey)
            key_hash = '00' + hash160pub(hex_str)
            sha = hashlib.sha256()
            sha.update( bytearray.fromhex(key_hash) )
            checksum = sha.digest()
            sha = hashlib.sha256()
            sha.update(checksum)
            checksum = sha.hexdigest()[0:8]

            print ( "checksum = \t" + sha.hexdigest() )
            print ( "key_hash + checksum = \t" + key_hash + ' ' + checksum )
            print ( "bitcoin address = \t" + (base58.b58encode( bytes(bytearray.fromhex(key_hash + checksum)) )).decode('utf-8') )
            f=open('add_info.txt','a')
            f.write( "\nchecksum = \t" + sha.hexdigest() )
            f.write( "\nkey_hash + checksum = \t" + key_hash + ' ' + checksum )
            f.write( "\nbitcoin address = \t" + (base58.b58encode( bytes(bytearray.fromhex(key_hash + checksum)) )).decode('utf-8') + '\n')
            f.close()

    elif start == 25:
        promptETH= '''
    ******************** Ethereum Address Balance and Info Check Tool ******************* 
    *                                                                                   *
    *    1-Ethereum Address Balance and Info Check Tool Single [Internet required]      *
    *    2-Ethereum Address Balance and Info Check Tool From File [Internet required]   *
    *                                                                                   *
    ******************** Ethereum Address Balance and Info Check Tool *******************
        '''
        print(promptETH)
        startETH=int(input(' Type 1-2 to Start = '))
        if startETH == 1:
            print ('Ethereum Address Balance and Info Check Tool')
            ethaddr = str(input('Enter Your ETH Address Here : '))
            contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)

            if contents.status_code==200:
                res = contents.json()
                balance = (res['balance'])
                txs = (res['txs'])
                addressinfo = (res['address'])
                if txs > 0:
                    nonTokenTxs = (res['nonTokenTxs'])
                    tokens = (res['tokens'])
                    print('[yellow] Ethereum Address Entered  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green] Number of Tokens:[green][' + str(nonTokenTxs) + '][/green]')
                    print('[yellow]Tokens   >> [ [/yellow]', tokens, '[yellow]][/yellow]')
                    time.sleep(3)
                else:
                    print('[yellow] Ethereum Address Entered  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                    time.sleep(3)    
        if startETH == 2:
            with open('eth.txt', newline='', encoding='utf-8') as f:
                for line in f:
                    mylist.append(line.strip())
            for i in range(0,len(mylist)):
                count+=1
                ethaddr = mylist[i]
                time.sleep(0.5)
                contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)
                if contents.status_code==200:
                    res = contents.json()
                    balance = (res['balance'])
                    txs = (res['txs'])
                    addressinfo = (res['address'])
                    if float(balance) > 0:
                        print('[yellow] Ethereum Address Entered  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                        print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                        with open("winner.txt", "a") as f:
                            f.write('\nEthereum (ETH) Address : ' + addressinfo + ' : No. TXS = ' + str(txs) + ' : Balance = ' + str(balance))
                            f.close   
                        time.sleep(3)
                    else:
                        print('[yellow] Ethereum Address Entered  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                        print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                
    elif start ==26:
        promptword= '''
    ************************* Mnemonic Words 12/15/18/21/24 tool ************************* 
    *                                                                                    *
    *    1-OWN WORDS to DEC & HEX with TX Check [Internet required]                      *
    *    2-Generated WORDS to DEC & HEX with TX Check [Internet required]                *
    *    Type 1-2 to Start                                                               *
    *                                                                                    *
    ************************* Mnemonic Words 12/15/18/21/24 tool *************************
        '''
        startwords=int(input(promptword))
        if startwords == 1:
            MNEMONIC: str = input(' Type your Own Words Here = ')
            Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
            if Lang == 1:
                Lang1 = "english"
            elif Lang == 2:
                Lang1 = "french"
            elif Lang == 3:
                Lang1 = "italian"
            elif Lang == 4:
                Lang1 = "spanish"
            elif Lang == 5:
                Lang1 = "chinese_simplified"
            elif Lang == 6:
                Lang1 = "chinese_traditional"
            elif Lang == 7:
                Lang1 = "japanese"
            elif Lang == 8:
                Lang1 = "korean"
            else:
                print("WRONG NUMBER!!! Starting with english")
                Lang1 = "english"
            PASSPHRASE: Optional[str] = None
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(
                mnemonic=MNEMONIC, language=Lang1, passphrase=PASSPHRASE
            )
            bip44_hdwallet.clean_derivation()
            mnemonic_words = bip44_hdwallet.mnemonic()
            ethaddr = bip44_hdwallet.address()
            HEX = bip44_hdwallet.private_key()
            dec = int(bip44_hdwallet.private_key(), 16)
            length = len(bin(dec))
            length -=2
            print('\nmnemonic_words  : ', mnemonic_words)
            print('\nPrivatekey (dec): ', dec, '  bits ', length, '\nPrivatekey (hex): ', HEX)
            contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)
            if contents.status_code==200:
                res = contents.json()
                balance = (res['balance'])
                txs = (res['txs'])
                addressinfo = (res['address'])
                print('[yellow] Ethereum Address  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                time.sleep(3)
        if startwords == 2:
            print('Mnemonic 12/15/18/21/24 Words to ETH Address Tool')
            R = int(input('Enter Ammount Mnemonic Words 12/15/18/21/24 : '))
            if R == 12:
                s1 = 128
            elif R == 15:
                s1 = 160
            elif R == 18:
                s1 = 192
            elif R == 21:
                s1 = 224
            elif R == 24:
                s1 = 256
            else:
                print("WRONG NUMBER!!! Starting with 24 Words")
                s1 = 256
            Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
            if Lang == 1:
                Lang1 = "english"
            elif Lang == 2:
                Lang1 = "french"
            elif Lang == 3:
                Lang1 = "italian"
            elif Lang == 4:
                Lang1 = "spanish"
            elif Lang == 5:
                Lang1 = "chinese_simplified"
            elif Lang == 6:
                Lang1 = "chinese_traditional"
            elif Lang == 7:
                Lang1 = "japanese"
            elif Lang == 8:
                Lang1 = "korean"
            else:
                print("WRONG NUMBER!!! Starting with english")
                Lang1 = "english"
            MNEMONIC: str = generate_mnemonic(language=Lang1, strength=s1)
            PASSPHRASE: Optional[str] = None
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(
                mnemonic=MNEMONIC, language=Lang1, passphrase=PASSPHRASE
            )
            bip44_hdwallet.clean_derivation()
            mnemonic_words = bip44_hdwallet.mnemonic()
            ethaddr = bip44_hdwallet.address()
            HEX = bip44_hdwallet.private_key()
            dec = int(bip44_hdwallet.private_key(), 16)
            length = len(bin(dec))
            length -=2
            print('\nmnemonic_words  : ', mnemonic_words)
            print('\nPrivatekey (dec): ', dec, '  bits ', length, '\nPrivatekey (hex): ', HEX)
            contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)
            if contents.status_code==200:
                res = contents.json()
                balance = (res['balance'])
                txs = (res['txs'])
                addressinfo = (res['address'])
                print('[yellow] Ethereum Address  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                time.sleep(3)
    elif start ==27:
        print('Mnemonic 12/15/18/21/24 Words to ETH Address Tool')
        R = int(input('Enter Ammount Mnemonic Words 12/15/18/21/24 : '))
        if R == 12:
            s1 = 128
        elif R == 15:
            s1 = 160
        elif R == 18:
            s1 = 192
        elif R == 21:
            s1 = 224
        elif R == 24:
            s1 = 256
        else:
            print("WRONG NUMBER!!! Starting with 24 Words")
            s1 = 256
        divs = int(input("How Many Derivation Paths? m/44'/60'/0'/0/0/ to m/44'/60'/0'/0/???? -> "))
        Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
        if Lang == 1:
            Lang1 = "english"
        elif Lang == 2:
            Lang1 = "french"
        elif Lang == 3:
            Lang1 = "italian"
        elif Lang == 4:
            Lang1 = "spanish"
        elif Lang == 5:
            Lang1 = "chinese_simplified"
        elif Lang == 6:
            Lang1 = "chinese_traditional"
        elif Lang == 7:
            Lang1 = "japanese"
        elif Lang == 8:
            Lang1 = "korean"
        else:
            print("WRONG NUMBER!!! Starting with english")
            Lang1 = "english"
        display = int(input('1=Full Display (Slower) 2=Slient Mode (Faster) : '))
        while True:
            data=[]
            count += 1
            total += divs
            MNEMONIC: str = generate_mnemonic(language=Lang1, strength=s1)
            PASSPHRASE: Optional[str] = None
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(
                mnemonic=MNEMONIC, language=Lang1, passphrase=PASSPHRASE
            )
            bip44_hdwallet.clean_derivation()
            mnemonic_words = bip44_hdwallet.mnemonic()
            data_eth()
            for target_wallet in data:
                address = target_wallet['address'].lower()
                if address in bloom_filter1:
                    print('\nMatch Found')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    print('Derivation Path : ', target_wallet['path'], ' : ETH Address : ', target_wallet['address'])
                    print('Privatekey  : ', target_wallet['privatekey'])
                    print('Privatekey DEC : ', target_wallet['privatedec'])
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey : {target_wallet['privatekey']}
                        Public Address ETH:  {target_wallet['address']}""")
            else:
                if display == 1:
                    print(' [' + str(count) + '] ------------------------')
                    print('Total Checked [' + str(total) + '] ')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    for bad_wallet in data:
                        print('Derivation Path : ', bad_wallet['path'], ' : ETH Address : ', bad_wallet['address'])
                        print('Privatekey : ', bad_wallet['privatekey'])
                        print('Privatekey DEC : ', bad_wallet['privatedec'])
                if display == 2:
                    print(' [' + str(count) + '] ------', 'Total Checked [' + str(total) + '] ', end='\r')
    elif start ==28:
        print('Mnemonic 12/15/18/21/24 Words to ETH Address Tool')
        R = int(input('Enter Ammount Mnemonic Words 12/15/18/21/24 : '))
        if R == 12:
            s1 = 128
        elif R == 15:
            s1 = 160
        elif R == 18:
            s1 = 192
        elif R == 21:
            s1 = 224
        elif R == 24:
            s1 = 256
        else:
            print("WRONG NUMBER!!! Starting with 24 Words")
            s1 = 256
        divs = int(input("How Many Derivation Paths? m/44'/60'/0'/0/0/ to m/44'/60'/0'/0/???? -> "))
        Lang = int(input(' Choose language 1.english, 2.french, 3.italian, 4.spanish, 5.chinese_simplified, 6.chinese_traditional, 7.japanese or 8.korean '))
        if Lang == 1:
            Lang1 = "english"
        elif Lang == 2:
            Lang1 = "french"
        elif Lang == 3:
            Lang1 = "italian"
        elif Lang == 4:
            Lang1 = "spanish"
        elif Lang == 5:
            Lang1 = "chinese_simplified"
        elif Lang == 6:
            Lang1 = "chinese_traditional"
        elif Lang == 7:
            Lang1 = "japanese"
        elif Lang == 8:
            Lang1 = "korean"
        else:
            print("WRONG NUMBER!!! Starting with english")
            Lang1 = "english"
        display = int(input('1=Full Display (Slower) 2=Slient Mode (Faster) : '))
        while True:
            data=[]
            count += 1
            total += divs
            MNEMONIC: str = generate_mnemonic(language=Lang1, strength=s1)
            PASSPHRASE: Optional[str] = None
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(
                mnemonic=MNEMONIC, language=Lang1, passphrase=PASSPHRASE
            )
            bip44_hdwallet.clean_derivation()
            mnemonic_words = bip44_hdwallet.mnemonic()
            data_eth()
            for target_wallet in data:
                ethaddr = target_wallet['address']
                contents = requests.get("https://ethbook.guarda.co/api/v2/address/" + ethaddr)
                if contents.status_code==200:
                    res = contents.json()
                    balance = (res['balance'])
                    txs = (res['txs'])
                    addressinfo = (res['address'])
                    print('Mnemonic_words:  ',mnemonic_words)
                    print('[yellow] Ethereum Address  >> [ [/yellow]', addressinfo, '[yellow]][/yellow]')
                    print('[red][*][/red] [yellow] >>[/yellow] Balance: [green] [' + str(balance) + '][/green] Transactions: [green][' +  str(txs) + '][/green]')
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey : {target_wallet['privatekey']}
                        Public Address ETH:  {target_wallet['address']}""")
    elif start ==29:
        promptdoge= '''
    *********************** Doge sequence Balance Check Tool *****************************
    *                                                                                    *
    *    ** Dogecoin sequence Balance Check Tool Requires internet                       *
    *    ** ANY MATCHING BALANCES GENERATED FOUND WILL SAVE TO(winner.txt)               *
    *                                                                                    *
    *********************** Doge sequence Balance Check Tool *****************************
        '''
        print(promptdoge)
        time.sleep(1)
        print("Start search... Pick Range to start (Min=0 Max=256)")
        x=int(input("Start range in BITs 0 or 255 (Max255) -> "))
        a = 2**x
        y=int(input("Stop range Max in BITs 256 Max (StopNumber)-> "))
        b = 2**y
        m=int(input("Magnitude Jump Stride -> "))
        print("Starting search... Please Wait min range: " + str(a))
        print("️Max range: " + str(b))
        P = a
        while P<b:
            P+=m
            ran= P
            seed = int(ran)
            HEX = "%064x" % ran
            dogeaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, seed) #DOGE
            dogeuaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, seed) #DOGE
            balanceDoge = get_doge(dogeaddr)
            balanceDoge1 = get_doge(dogeuaddr)
            time.sleep(1.0) #Can be removed
            if float(balanceDoge) > float(ammount) or float(balanceDoge1) < ammount:
                print('\n Match Found')
                print('\nPrivatekey (dec): ', seed,'\nPrivatekey (hex): ', HEX, '\nPublic Address DOGE Uncompressed : ', dogeuaddr, '  Balance = ',  str(balanceDoge1), '\nPublic Address DOGE Compressed   : ', dogeaddr, '  Balance = ',  str(balanceDoge))
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(seed))
                f.write('\nPrivatekey (hex): ' + HEX)
                f.write('\nPublic Address DOGE Compressed: ' + dogeaddr  + ' : ' +  str(balanceDoge))
                f.write('\nPublic Address DOGE Uncompressed: ' + dogeuaddr  + ' : ' +  str(balanceDoge1))
                f.write('\n============================================================')
                f.close()
            else:
                print('\nPrivatekey (dec): ', seed,'\nPrivatekey (hex): ', HEX, '\nPublic Address DOGE Uncompressed : ', dogeuaddr, '  Balance = ',  str(balanceDoge1), '\nPublic Address DOGE Compressed   : ', dogeaddr, '  Balance = ',  str(balanceDoge))
            
    elif start ==30:
        promptdoge= '''
    *********************** Doge Random Balance Check Tool *****************************
    *                                                                                    *
    *    ** Dogecoin sequence Random Check Tool Requires internet                        *
    *    ** ANY MATCHING BALANCES GENERATED FOUND WILL SAVE TO(winner.txt)               *
    *                                                                                    *
    *********************** Doge Random Balance Check Tool *****************************
        '''
        print(promptdoge)
        time.sleep(1)
        print("Start search... Pick Range to start (Min=0 Max=256)")
        x=int(input("Start range in BITs 0 or 255 (Max255) -> "))
        start = 2**x
        y=int(input("Stop range Max in BITs 256 Max (StopNumber)-> "))
        stop = 2**y
        print("Starting search... Please Wait min range: " + str(start))
        print("️Max range: " + str(stop))
        while True:
            ran=random.randrange(start,stop)
            seed = int(ran)
            HEX = "%064x" % ran
            dogeaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, True, seed) #DOGE
            dogeuaddr = ice.privatekey_to_coinaddress(ice.COIN_DOGE, 0, False, seed) #DOGE
            balanceDoge = get_doge(dogeaddr)
            balanceDoge1 = get_doge(dogeuaddr)
            time.sleep(1.0) #Can be removed
            if float(balanceDoge) > float(ammount) or float(balanceDoge1) < ammount:
                print('\n Match Found')
                print('\nPrivatekey (dec): ', seed,'\nPrivatekey (hex): ', HEX, '\nPublic Address DOGE Uncompressed : ', dogeuaddr, '  Balance = ',  str(balanceDoge1), '\nPublic Address DOGE Compressed   : ', dogeaddr, '  Balance = ',  str(balanceDoge))
                f=open("winner.txt","a")
                f.write('\nPrivatekey (dec): ' + str(seed))
                f.write('\nPrivatekey (hex): ' + HEX)
                f.write('\nPublic Address DOGE Compressed: ' + dogeaddr  + ' : ' +  str(balanceDoge))
                f.write('\nPublic Address DOGE Uncompressed: ' + dogeuaddr  + ' : ' +  str(balanceDoge1))
                f.write('\n============================================================')
                f.close()
            else:
                print('\nPrivatekey (dec): ', seed,'\nPrivatekey (hex): ', HEX, '\nPublic Address DOGE Uncompressed : ', dogeuaddr, '  Balance = ',  str(balanceDoge1), '\nPublic Address DOGE Compressed   : ', dogeaddr, '  Balance = ',  str(balanceDoge))
    else:
        print('WRONG NUMBER!!! MUST CHOSE 1 - 30 ')