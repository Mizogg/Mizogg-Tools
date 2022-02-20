# -*- coding: utf-8 -*-
'''
Сделано Mizogg Tools для помощи в поиске биткойнов. Удачи и счастливой охоты Miz_Tools_ice_RU.py Версия 4 Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4 
21 Bitcoin Tools
Using iceland2k14 secp256k1 https://github.com/iceland2k14/secp256k1  fastest Python Libary

https://mizogg.co.uk
'''
import requests, codecs, hashlib, ecdsa, bip32utils, binascii, sys, time, random, itertools
from bit.base58 import b58decode_check
from bit.utils import bytes_to_hex
import secp256k1 as ice
from mnemonic import Mnemonic
from bit import *
from bit.format import bytes_to_wif
from urllib.request import urlopen
from time import sleep

n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def get_balance(addr):
    contents = requests.get('https://sochain.com/api/v2/get_address_balance/BTC/' + addr, timeout=10)
    res = contents.json()
    response = (contents.content)
    balance = dict(res['data'])['confirmed_balance']
    return balance

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
"""
@author: iceland
"""

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

#==============================================================================
def get_rawtx_from_blockchain(txid):
    try:
        htmlfile = urlopen("https://blockchain.info/rawtx/%s?format=hex" % txid, timeout = 20)
    except:
        print('Unable to connect internet to fetch RawTx. Exiting..')
        sys.exit(1)
    else: res = htmlfile.read().decode('utf-8')
    return res
# =============================================================================

def getSignableTxn(parsed):
    res = []
    first, inp_list, rest = parsed
    tot = len(inp_list)
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

prompt= '''
    ************************ Главное меню Mizogg's Tools ********************************************
    *                       Инструменты одиночной проверки                                          *
    *  Вариант 1. Биткойн-адрес с проверкой баланса                                 =  1            *
    *  Вариант 2. Биткойн-адрес на HASH160                                          =  2            *
    *  Вариант 3. HASH160 на биткойн-адрес (не работает)                            =  3            *
    *  Вариант 4. Мозговой кошелек Биткойн с проверкой баланса                      =  4            *
    *  Вариант 5. Шестнадцатеричный код в десятичный (HEX 2 DEC)                    =  5            *
    *  Вариант 6. Десятичный в шестнадцатеричный (DEC 2 HEX)                        =  6            *
    *  Вариант 7. Шестнадцатеричный адрес в биткойн с проверкой баланса             =  7            *
    *  Вариант 8. Десятичный адрес в биткойн с проверкой баланса                    =  8            *
    *  Вариант 9. Мнемонические слова для биткойн-адреса с проверкой баланса        =  9            *
    *  Вариант 10.WIF на биткойн-адрес с проверкой баланса                          =  10           *
    *  Вариант 11.Получить подпись ECDSA R, S, Z с помощью инструмента rawtx или txid = 11          *
    *  Вариант 12.Разделение диапазона IN HEX или DEC инструмент                   =  12            *
    *                                                                                               *
    *                    Генераторы и мультипроверочные инструменты                                 *
    *  Вариант 13. Биткойн-адреса из файла с проверкой баланса                      = 13            *
    *  Вариант 14. Биткойн-адреса из файла в файл HASH160                           = 14            *
    *  Вариант 15. Список Brain Wallet из файла с проверкой баланса                 = 15            *
    *  Вариант 16. Генератор мнемонических слов, случайный выбор [офлайн]           = 16            *
    *  Вариант 17. Случайное сканирование биткойнов в случайном порядке в диапазоне = 17            *
    *  Вариант 18. Последовательность биткойнов сканируется последовательно в диапазоне деления= 18 *
    *  Вариант 19. Биткойн случайная обратная позиция K                             = 19            *
    *  Вариант 20. Последовательность биткойнов, обратная K позиция                 = 20            *
    *  Вариант 21. Биткойн WIF Recovery или WIF Checker (только начиная с 5)        = 21            *
    *                                                                                               *
    *               Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4                                    *
    ************ Главное меню Mizogg's Tools Using iceland2k14 secp256k1 ****************************

Введите свой выбор здесь Enter 1-21 : 
'''


while True:
    data = []
    mylist = []
    count=0
    ammount = 0.00000000
    total= 0
    iteration = 0
    start_time = time.time()
    start=int(input(prompt))
    if start == 1:
        print ('Инструмент проверки баланса адреса')
        addr = str(input('Введите здесь свой биткойн-адрес : '))
        print ('\nBitcoin Address = ', addr, '    Balance = ', get_balance(addr), ' BTC')
    elif start == 2:
        print ('Адрес для инструмента HASH160')
        addr = str(input('Введите здесь свой биткойн-адрес : '))
        hash160=b58decode_check(addr)
        address_hash160 = bytes_to_hex(hash160)[2:]
        print ('\nBitcoin Address = ', addr, '\nTo HASH160 = ', address_hash160)
    elif start == 3:
        print ('Инструмент HASH160 для биткойн-адреса')
        hash160 =(str(input('Введите свой HASH160 здесь : ')))
        print ('Скоро не работает')
    elif start == 4:
        print ('Мозговой кошелек Биткойн Адрес Инструмент')    
        passphrase = (input("Введите пароль ЗДЕСЬ : "))
        wallet = BrainWallet()
        private_key, addr = wallet.generate_address_from_passphrase(passphrase)
        print('\nPassphrase     = ',passphrase)
        print('Private Key      = ',private_key)
        print('Bitcoin Address  = ', addr, '    Balance = ', get_balance(addr), ' BTC')
    elif start == 5:
        print('Шестнадцатеричный в десятичный инструмент')
        HEX = str(input('Введите свой шестнадцатеричный HEX здесь : '))
        dec = int(HEX, 16)
        print('\nHexadecimal = ',HEX, '\nTo Decimal = ', dec)
    elif start == 6:
        print('Десятичный в шестнадцатеричный инструмент')
        dec = int(input('Введите свой десятичный DEC здесь : '))
        HEX = "%064x" % dec
        print('\nDecimal = ', dec, '\nTo Hexadecimal = ', HEX)
    elif start == 7:
        print('Инструмент преобразования шестнадцатеричного адреса в биткойн')
        HEX=str(input("Шестнадцатеричный HEX ->  "))
        dec = int(HEX, 16)
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        caddr = ice.privatekey_to_address(0, True, dec) #Compressed
        uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
        p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
        bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
        query = {caddr}|{uaddr}|{p2sh}|{bech32}
        request = requests.get("https://blockchain.info/multiaddr?active=" + ','.join(query), timeout=10)
        try:
            request = request.json()
            print('PrivateKey (hex) : ', HEX)
            print('PrivateKey (dec) : ', dec)
            print('PrivateKey (wif) Compressed   : ', wifc)
            print('PrivateKey (wif) UnCompressed : ', wifu)
            print('Bitcoin Address Compressed   = ', caddr, '    Balance = ', get_balance(caddr), ' BTC')
            print('Bitcoin Address UnCompressed = ', uaddr, '    Balance = ', get_balance(uaddr), ' BTC')
            print('Bitcoin Address p2sh         = ', p2sh, '    Balance = ', get_balance(p2sh), ' BTC')
            print('Bitcoin Address Bc1  bech32  = ', bech32, '    Balance = ', get_balance(bech32), ' BTC')
            for row in request["addresses"]:
                print(row)
        except:
            pass
    elif start == 8:
        print('Инструмент преобразования десятичного адреса в биткойн')
        dec=int(input('Десятичный Dec (Максимум 115792089237316195423570985008687907852837564279074904382605163141518161494336 ) ->  '))
        HEX = "%064x" % dec  
        wifc = ice.btc_pvk_to_wif(HEX)
        wifu = ice.btc_pvk_to_wif(HEX, False)
        caddr = ice.privatekey_to_address(0, True, dec) #Compressed
        uaddr = ice.privatekey_to_address(0, False, dec)  #Uncompressed
        p2sh = ice.privatekey_to_address(1, True, dec) #p2sh
        bech32 = ice.privatekey_to_address(2, True, dec)  #bech32
        query = {caddr}|{uaddr}|{p2sh}|{bech32}
        request = requests.get("https://blockchain.info/multiaddr?active=" + ','.join(query), timeout=10)
        try:
            request = request.json()
            print('PrivateKey (hex) : ', HEX)
            print('PrivateKey (dec) : ', dec)
            print('PrivateKey (wif) Compressed   : ', wifc)
            print('PrivateKey (wif) UnCompressed : ', wifu)
            print('Bitcoin Address Compressed   = ', caddr, '    Balance = ', get_balance(caddr), ' BTC')
            print('Bitcoin Address UnCompressed = ', uaddr, '    Balance = ', get_balance(uaddr), ' BTC')
            print('Bitcoin Address p2sh         = ', p2sh, '    Balance = ', get_balance(p2sh), ' BTC')
            print('Bitcoin Address Bc1  bech32  = ', bech32, '    Balance = ', get_balance(bech32), ' BTC')
            for row in request["addresses"]:
                print(row)
        except:
            pass
    elif start == 9:
        print('Мнемоника 12/15/18/21/24 Words to Bitcoin Address Tool')
        wordlist = str(input('Введите свои мнемонические слова = '))
        mnemo = Mnemonic("english")
        mnemonic_words = wordlist
        seed = mnemo.to_seed(mnemonic_words, passphrase="")
        data_wallet()
        for target_wallet in data:
            print('\nmnemonic_words  : ', mnemonic_words, '\nDerivation Path : ', target_wallet['path'], '\nBitcoin Address : ', target_wallet['address'], ' Balance = ', get_balance(target_wallet['address']), ' BTC', '\nPrivatekey WIF  : ', target_wallet['privatekey'])
    elif start == 10:
        print('WIF to Bitcoin Address Tool')
        WIF = str(input('Enter Your Wallet Import Format WIF = '))
        addr = Key(WIF).address
        print('\nWallet Import Format WIF = ', WIF)
        print('Bitcoin Address  = ', addr, '    Balance = ', get_balance(addr), ' BTC')
    elif start == 11:
        promptrsz= '''
    ********************** Получить подпись ECDSA R, S, Z инструмент rawtx или txid ********************************* 
    *                                                                                                               *
    *1-txid  Начинается расчет R,S,Z API блокчейна. [Требуется Интернет]                                            *
    *2-rawtx R, S, Z, Pubkey для каждого из входных данных, присутствующих в данных rawtx. [Интернет не требуется]  *
    *    Введите 1-2, чтобы начать                                                                                  *
    *                                                                                                               *
    ********************** Получить подпись ECDSA R, S, Z инструмент rawtx или txid ********************************* 
        '''
        startrsz=int(input(promptrsz))
        if startrsz == 1:
            txid = str(input('Введите ваш -txid = ')) #'82e5e1689ee396c8416b94c86aed9f4fe793a0fa2fa729df4a8312a287bc2d5e'
            rawtx = get_rawtx_from_blockchain(txid)
        elif startrsz == 2:
            rawtx =str(input('Введите ваш -rawtx = ')) #'01000000028370ef64eb83519fd14f9d74826059b4ce00eae33b5473629486076c5b3bf215000000008c4930460221009bf436ce1f12979ff47b4671f16b06a71e74269005c19178384e9d267e50bbe9022100c7eabd8cf796a78d8a7032f99105cdcb1ae75cd8b518ed4efe14247fb00c9622014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffffb0385cd9a933545628469aa1b7c151b85cc4a087760a300e855af079eacd25c5000000008b48304502210094b12a2dd0f59b3b4b84e6db0eb4ba4460696a4f3abf5cc6e241bbdb08163b45022007eaf632f320b5d9d58f1e8d186ccebabea93bad4a6a282a3c472393fe756bfb014104e3896e6cabfa05a332368443877d826efc7ace23019bd5c2bc7497f3711f009e873b1fcc03222f118a6ff696efa9ec9bb3678447aae159491c75468dcc245a6cffffffff01404b4c00000000001976a91402d8103ac969fe0b92ba04ca8007e729684031b088ac00000000'
        else:
            print("НЕПРАВИЛЬНЫЙ НОМЕР!!! ДОЛЖЕН ВЫБРАТЬ 1 - 2 ")
            break

        print('\nСтартовая программа...')

        m = parseTx(rawtx)
        e = getSignableTxn(m)

        for i in range(len(e)):
            print('='*70,f'\n[Input Index #: {i}]\n     R: {e[i][0]}\n     S: {e[i][1]}\n     Z: {e[i][2]}\nPubKey: {e[i][3]}')
    elif start == 12:
        prompt123= '''
            **************** Инструменты разделения диапазона *********************
            *          Разделить диапазон в битах или байтах                      *
            *               Вариант 1 Разделить диапазон в битах = 1              *
            *               Вариант 2 Разделить диапазон в байтах = 2             *
            **************** Инструменты разделения диапазона *********************
        Введите свой выбор здесь Введите 1-2 :
        '''
        promptstart=int(input(prompt123))
        if promptstart == 1:
            x=int(input("Биты начального диапазона Мин. 1–255 ->  "))
            y=int(input("биты диапазона остановки Макс. 256 -> "))
            start=2**x
            stop=2**y
            
        elif promptstart == 2:    
            start=int(input("начальный диапазон Мин. байт 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
            stop=int(input("диапазон остановки Макс. байт 115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))

        rangediv=int(input("Раздел диапазона 1% t0 ???% ->  "))
        display =int(input("Выберите метод Метод отображения: 1 - HEX:; 2 - ДЕК  "))

        remainingtotal=stop-start
        div = round(remainingtotal / rangediv)
           
        divsion = []
               
        if display == 1:
            divsion = []
            divsion_wallet()
            for data_w in divsion:
                HEX = data_w['HEX']
                print('Процентов', data_w['percent'], ' : Privatekey (hex): ', data_w['HEX'])
                with open("hex.txt", "a") as f:
                    f.write(f"""\nПроцентов{data_w['percent']} Privatekey (hex): {data_w['HEX']}""")
                    f.close
        elif display == 2:
            divsion = []
            divsion_wallet()
            for data_w in divsion:
                seed = data_w['seed']
                print('Процентов', data_w['percent'], ' : Privatekey (dec): ', data_w['seed'])
                with open("dec.txt", "a") as f:
                    f.write(f"""\nПроцентов{data_w['percent']} Privatekey (dec): {data_w['seed']}""")
                    f.close
        else:
            print("НЕПРАВИЛЬНЫЙ НОМЕР!!! ДОЛЖЕН ВЫБРАТЬ 1 - 2 ")
                
    elif start == 13:
        promptchk= '''
    ************************* Биткойн-адреса из файла с проверкой баланса ************************* 
    *                                                                                             *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком биткойн-адресов.             *
    *    ** Ваш список адресов будет проверен на наличие баланса [требуется Интернет]             *
    *    ** ЛЮБЫЕ БИТКОИН-КОШЕЛЬКИ, НАЙДЕННЫЕ С БАЛАНСОМ, БУДУТ СОХРАНЕНЫ НА (balance.txt)        *
    *                                                                                             *
    ************************* Биткойн-адреса из файла с проверкой баланса *************************
        '''
        print(promptchk)
        time.sleep(0.5)
        print('Биткойн-адреса загружаются, пожалуйста, подождите..................................:')
        with open("btc.txt", "r") as file:
            line_count = 0
            for line in file:
                line != "\n"
                line_count += 1
        with open('btc.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Всего биткойн-адресов загружено now Checking Balance ', line_count)
        remaining=line_count
        for i in range(0,len(mylist)):
            count+=1
            remaining-=1
            addr = mylist[i]
            time.sleep(0.5)
            if float (get_balance(addr)) > ammount:
                print ('\nBitcoin Address = ', addr, '    Остаток средств = ', get_balance(addr), ' BTC')
                f=open('balance.txt','a')
                f.write('\nBitcoin Address = ' + addr + '    Остаток средств = ' + get_balance(addr) + ' BTC')
                f.close()
            else:
                print ('\nНомер сканирования = ',count, ' == Оставшийся = ', remaining)
                print ('\nBitcoin Address = ', addr, '    Остаток средств = ', get_balance(addr), ' BTC')
    elif start == 14:
        prompthash= '''
    *********************** Биткойн-адреса из файла в файл HASH160 Инструмент *********************** 
    *                                                                                                *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком биткойн-адресов.                *
    *    ** Ваш список адресов будет преобразован в HASH160 [Интернет не требуется]                  *
    *    ** Адреса HASH160 будут сохранены в файл с именем hash160.txt.                              *
    *                                                                                                *
    *********************** Биткойн-адреса из файла в файл HASH160 Инструмент ************************
        '''
        print(prompthash)
        time.sleep(0.5)
        print('Биткойн-адреса загружаются, пожалуйста, подождите..................................:')
        with open("btc.txt", "r") as file:
            line_count = 0
            for line in file:
                line != "\n"
                line_count += 1
        with open('btc.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Всего биткойн-адресов загружено теперь конвертируем в HASH160 ', line_count)
        remaining=line_count
        for i in range(0,len(mylist)):
            count+=1
            remaining-=1
            addr = mylist[i]
            hash160=b58decode_check(addr)
            address_hash160 = bytes_to_hex(hash160)[2:]
            print ('\nBitcoin Address = ', addr, '\nTo HASH160 = ', address_hash160)
            f=open('hash160.txt','a')
            f.write('\n' + address_hash160)
            f.close()
    elif start == 15:
        promptbrain= '''
    *********************** Список кошельков Brain из файла с помощью инструмента проверки баланса ******
    *                                                                                                   *
    *    ** Для этого инструмента требуется файл с именем brainwords.txt со списком слов Brain Wallet.  *
    *    ** Ваш список будет конвертирован в биткойны, а баланс проверен [требуется Интернет]           *
    *    ** ЛЮБЫЕ КОШЕЛЬКИ BRAIN, НАЙДЕННЫЕ С БАЛАНСОМ, БУДУТ СОХРАНЯТЬСЯ В (winner.txt)                *
    *                                                                                                   *
    ************* Список кошельков Brain из файла с помощью инструмента проверки баланса ****************
        '''
        print(promptbrain)
        time.sleep(0.5)
        print('ЗАГРУЗКА СПИСКА ПАРОЛЕЙ КОШЕЛЬКА BRAIN>>>>')
        with open("brainwords.txt", "r") as file:
            line_count = 0
            for line in file:
                line != "\n"
                line_count += 1
        with open('brainwords.txt', newline='', encoding='utf-8') as f:
            for line in f:
                mylist.append(line.strip())
        print('Всего загружен пароль кошелька Brain:', line_count)
        remaining=line_count
        for i in range(0,len(mylist)):
            time.sleep(0.5)
            count+=1
            remaining-=1
            passphrase = mylist[i]
            wallet = BrainWallet()
            private_key, addr = wallet.generate_address_from_passphrase(passphrase)
            if float (get_balance(addr)) > ammount:
                print ('\nBitcoin Address = ', addr, '    Остаток средств = ', get_balance(addr), ' BTC')
                print('Passphrase       : ',passphrase)
                print('Private Key      : ',private_key)
                print('Номер сканирования : ', count, ' : Оставшиеся пароли : ', remaining)
                f=open('winner.txt','a')
                f.write('\nBitcoin Address = ' + addr + '    Остаток средств = ' + get_balance(addr) + ' BTC')
                f.write('\nPassphrase       : '+ passphrase)
                f.write('\nPrivate Key      : '+ private_key)
                f.close()
            else:
                print ('\nScan Number = ',count, ' == Оставшиеся пароли = ', remaining)
                print ('\nBitcoin Address = ', addr, '    Остаток средств = ', get_balance(addr), ' BTC')
    elif start == 16:
        promptMnemonic= '''
    *********************** Генератор мнемонических слов Random [Offline] *************************
    *                                                                                             *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком баз данных биткойн-адресов.  *
    *    ** ЛЮБЫЕ МНЕМОНИЧЕСКИЕ СЛОВА, СООТВЕТСТВУЮЩИЕ БАЗЕ ДАННЫХ BTC, СОХРАНЯЮТСЯ В (winner.txt)*
    *                                                                                             *
    *********************** Генератор мнемонических слов Random [Offline] *************************
        '''
        print(promptMnemonic)
        time.sleep(0.5)
        filename ='btc.txt'
        with open(filename) as f:
            line_count = 0
            for line in f:
                line != "\n"
                line_count += 1        
        with open(filename) as file:
            add = file.read().split()
        add = set(add)
        print('Всего биткойн-адресов загружено ', line_count)        
        print('Мнемоника 12/15/18/21/24 Words to Bitcoin Address Tool')
        R = int(input('Введите количество мнемонических слов 12/15/18/21/24:'))
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
            print("НЕПРАВИЛЬНЫЙ НОМЕР!!! Начиная с 24 слов")
            s1 = 256
        while True:
            data=[]
            count += 1
            total += 20
            mnemo = Mnemonic("english")
            mnemonic_words = mnemo.generate(strength=s1)
            seed = mnemo.to_seed(mnemonic_words, passphrase="")
            entropy = mnemo.to_entropy(mnemonic_words)
            data_wallet()
            for target_wallet in data:
                address = target_wallet['address']
                if address in add:
                    print('\nMatch Found')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    print('Derivation Path : ', target_wallet['path'], ' : Bitcoin Address : ', target_wallet['address'])
                    print('Privatekey WIF  : ', target_wallet['privatekey'])
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey WIF:  {target_wallet['privatekey']}
                        Public Address Bitcoin:  {target_wallet['address']}
                        =====Made by mizogg.co.uk Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4 =====""")
            else:
                print(' [' + str(count) + '] ------------------------')
                print('Total Checked [' + str(total) + '] ')
                print('\nmnemonic_words  : ', mnemonic_words)
                for bad_wallet in data:
                    print('Derivation Path : ', bad_wallet['path'], ' : Bitcoin Address : ', bad_wallet['address'])
                    print('Privatekey WIF  : ', bad_wallet['privatekey'])
    elif start == 17:
        promptrandom= '''
    *********************** Случайное сканирование биткойнов в случайном порядке в Range Tool ***********
    *                                                                                                   *
    *    ** Случайное сканирование биткойнов случайным образом в диапазоне [Offline]                    *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком баз данных биткойн-адресов.        *
    *    ** ЛЮБЫЕ СООТВЕТСТВУЮЩИЕ КОШЕЛЬКИ, СООТВЕТСТВУЮЩИЕ БАЗЕ ДАННЫХ BTC, СОХРАНЯЮТ В (winner.txt)   *
    *                                                                                                   *
    *******[+] Запуск....Пожалуйста, подождите....Загружается список биткойн-адресов....*****************
        '''
        print(promptrandom)
        time.sleep(0.5)
        filename ='btc.txt'
        with open(filename) as f:
            line_count = 0
            for line in f:
                line != "\n"
                line_count += 1
        with open(filename) as file:
            add = file.read().split()
        add = set(add)
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count)) 
        start=int(input("начальный диапазон Мин. 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
        stop=int(input("диапазон остановки Макс.115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))
        print("Начинается поиск... Пожалуйста, подождите мин. диапазон: " + str(start))
        print("Максимальный диапазон: " + str(stop))
        print("==========================================================")
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))    
        while True:
            count += 4
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

            if caddr in add or uaddr in add or P2SH in add or BECH32 in add :
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
                    elapsed = time.time() - start_time
                    print(f'It/CPU={iteration} checked={count} Hex={HEX} Keys/Sec={iteration / elapsed:.1f}')
    elif start == 18:
        promptsequence= '''
    *********************** Биткойн-последовательность Division in Range Tool ***************************
    *                                                                                                   *
    *    ** Последовательность биткойнов и деление диапазона на 1%-1000000%                             *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком баз данных биткойн-адресов.        *
    *    ** ЛЮБЫЕ СООТВЕТСТВУЮЩИЕ КОШЕЛЬКИ, СООТВЕТСТВУЮЩИЕ БАЗЕ ДАННЫХ BTC, СОХРАНЯЮТ В (winner.txt)   *
    *                                                                                                   *
    *******[+] Запуск....Пожалуйста, подождите....Загружается список биткойн-адресов....*****************
        '''
        print(promptsequence)
        time.sleep(0.5)
        filename ='btc.txt'
        with open(filename) as f:
            line_count = 0
            for line in f:
                line != "\n"
                line_count += 1
        with open(filename) as file:
            add = file.read().split()
        add = set(add)
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count)) 
        start=int(input("начальный диапазон Мин. 1-115792089237316195423570985008687907852837564279074904382605163141518161494335 ->  "))
        stop=int(input("диапазон остановки Макс.115792089237316195423570985008687907852837564279074904382605163141518161494336 -> "))
        mag=int(input("Величина прыжкового шага -> "))
        rangediv=int(input("Раздел диапазона 1% t0 ???% ->  "))
        display =int(input("Выберите метод Метод отображения: 1 - Меньше деталей: (Самый быстрый); 2 - Шестнадцатеричные детали: (медленнее); 3 - Детали кошелька: (медленнее)  "))
        print("Начинается поиск... Пожалуйста, подождите мин. диапазон: " + str(start))
        print("Максимальный диапазон: " + str(stop))
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))

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
                    if caddr in add or uaddr in add or p2sh in add or bech32 in add:
                        print('\nСовпадение найдено в : ', data_w['percent'])
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
                            Public Address bc1 BECH32:  {data_w['bech32']}
                            =====Made by mizogg.co.uk Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4 =====""")
                            
                    else:
                        if display == 1:
                            print('Сканировать: ', count , ' :Оставшийся: ', str(finish), ' :Всего: ', str(total), end='\r')
                        elif display == 2:
                            for bad_wallet in data:
                                print(bad_wallet['percent'], '\nPrivatekey (hex): ', bad_wallet['HEX'], end='\r')
                        elif display == 3:
                            for bad_wallet in data:
                                print(bad_wallet['percent'])
                                print('\nPrivatekey (dec): ', bad_wallet['seed'], '\nPrivatekey (hex): ', bad_wallet['HEX'], '\nPrivatekey Uncompressed: ', bad_wallet['wifu'], '\nPrivatekey compressed: ', bad_wallet['wifc'], '\nPublic Address 1 Uncompressed: ', bad_wallet['uaddr'], '\nPublic Address 1 compressed: ', bad_wallet['caddr'], '\nPublic Address 3 P2SH: ', bad_wallet['p2sh'], '\nPublic Address bc1 BECH32: ', bad_wallet['bech32'])
                        else:
                            print("НЕПРАВИЛЬНЫЙ НОМЕР!!! ДОЛЖЕН ВЫБРАТЬ 1, 2 или 3")
                            break
                        
                                
            except(KeyboardInterrupt, SystemExit):
                exit('\nОбнаружено сочетание клавиш CTRL-C. Выход изящно. Спасибо и удачной охоты')
    elif start == 19:
        promptinverse= '''
    *********************** Инструмент случайного обратного диапазона биткойнов K ***********************
    *                                                                                                   *
    *    ** Биткойн Случайный инверсный K-диапазон                                                      *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком баз данных биткойн-адресов.        *
    *    ** ЛЮБЫЕ СООТВЕТСТВУЮЩИЕ КОШЕЛЬКИ, СООТВЕТСТВУЮЩИЕ БАЗЕ ДАННЫХ BTC, СОХРАНЯЮТ В (winner.txt)   *
    *                                                                                                   *
    ********[+] Запуск.........Пожалуйста, подождите.....Загружается список адресов биткойнов.....*******
        '''
        print(promptinverse)
        time.sleep(0.5)
        filename ='btc.txt'
        with open(filename) as f:
            line_count = 0
            for line in f:
                line != "\n"
                line_count += 1
        with open(filename) as file:
            add = file.read().split()
        add = set(add)
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))  
        start = int(input("начальный диапазон Мин. 1-57896044618658097711785492504343953926418782139537452191302581570759080747168 ->  "))
        stop = int(input("диапазон остановки МАКС. 57896044618658097711785492504343953926418782139537452191302581570759080747169 ->  "))
        print("Начинается поиск... Пожалуйста, подождите мин. диапазон: " + str(start))
        print("Максимальный диапазон: " + str(stop))
        print("==========================================================")
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))
        while True:
            count += 8
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
            if caddrk1 in add or uaddrk1 in add or P2SHk1 in add or BECH32k1 in add :
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
            if caddrk2 in add or uaddrk2 in add or P2SHk2 in add or BECH32k2 in add :
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
                    elapsed = time.time() - start_time
                    addper= round(iteration / elapsed)*8
                    print(f'It/CPU={iteration} checked={count} Address/Sec={addper} Keys/Sec={iteration / elapsed:.1f}')
    elif start == 20:
        promptinversesq= '''
    *********************** Биткойн-последовательность Inverse K Range Tool *****************************
    *                                                                                                   *
    *    ** Биткойн-последовательность, обратный K-диапазон                                             *
    *    ** Этому инструменту нужен файл с именем bct.txt со списком баз данных биткойн-адресов.        *
    *    ** ЛЮБЫЕ СООТВЕТСТВУЮЩИЕ КОШЕЛЬКИ, СООТВЕТСТВУЮЩИЕ БАЗЕ ДАННЫХ BTC, СОХРАНЯЮТ В (winner.txt)   *
    *                                                                                                   *
    ******[+] Запуск.........Пожалуйста, подождите.....Загружается список адресов биткойнов.....*********
        '''
        print(promptinversesq)
        time.sleep(0.5)
        filename ='btc.txt'
        with open(filename) as f:
            line_count = 0
            for line in f:
                line != "\n"
                line_count += 1
        with open(filename) as file:
            add = file.read().split()
        add = set(add)
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))  
        start = int(input("начальный диапазон Мин. 1-57896044618658097711785492504343953926418782139537452191302581570759080747168 ->  "))
        stop = int(input("диапазон остановки МАКС. 57896044618658097711785492504343953926418782139537452191302581570759080747169 ->  "))
        mag=int(input("Величина прыжкового шага -> "))
        print("Начинается поиск... Пожалуйста, подождите мин. диапазон: " + str(start))
        print("Максимальный диапазон: " + str(stop))
        print("==========================================================")
        print('Всего биткойн-адресов загружено и проверено : ',str (line_count))
        while start < stop:
            count += 8
            iteration += 1
            start+=mag
            k1 = int(start)
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
            if caddrk1 in add or uaddrk1 in add or P2SHk1 in add or BECH32k1 in add :
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
            if caddrk2 in add or uaddrk2 in add or P2SHk2 in add or BECH32k2 in add :
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
                    elapsed = time.time() - start_time
                    addper= round(iteration / elapsed)*8
                    print(f'It/CPU={iteration} checked={count} Address/Sec={addper} Keys/Sec={iteration / elapsed:.1f}')
        
        
    elif start == 21:
        promptWIF= '''
    *********************** Биткойн WIF Recovery или инструмент проверки WIF ************************
    *                                                                                               *
    *    ** Найдите недостающие части формата импорта кошелька (WIF) для биткойнов                  *
    *    ** Этот инструмент работает только с WIF Starting 5 (позже будет улучшено)                 *
    *    ** ЛЮБОЙ СООТВЕТСТВУЮЩИЙ WIF, СОЗДАННЫЙ ЭТОМУ АДРЕСУ СОВПАДЕНИЯ, СОХРАНИТ В (winner.txt)   *
    *                                                                                               *
    *********************** Биткойн WIF Recovery или инструмент проверки WIF ************************
        '''
        print(promptWIF)
        time.sleep(0.5)   
        start= str(input('Введите WIF ЗДЕСЬ или узнайте начальную часть : '))
        miss = int(input('Сколько пропущенных символов Введите 0, если нет: '))
        if miss == 0:
            private_key_WIF = start
            first_encode = base58.b58decode(private_key_WIF)
            private_key_full = binascii.hexlify(first_encode)
            private_key = private_key_full[2:-8]
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
            stop = str(input('Выйти из банка или ввести конечную часть : '))
            add= str(input('Введите биткойн-адрес Ищете совпадение с WIF = '))
            for a in iter_all(miss):
                total+=1
                private_key_WIF = a + stop
                first_encode = base58.b58decode(private_key_WIF)
                private_key_full = binascii.hexlify(first_encode)
                private_key = private_key_full[2:-8]
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
                          
    else:
        print("НЕПРАВИЛЬНЫЙ НОМЕР!!! ДОЛЖЕН ВЫБРАТЬ 1 - 21 ")
        break
