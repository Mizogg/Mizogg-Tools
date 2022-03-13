#!/usr/bin/env python3
# miz_tools_ethV2.py Using tatum.io API
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.derivations import BIP44Derivation
from hdwallet.utils import generate_mnemonic
from hdwallet import HDWallet
from typing import Optional
import random, requests, time
from hdwallet.symbols import ETH as SYMBOL

def eth_bal(ethadd):
    balance_url = "https://api-eu1.tatum.io/v3/ethereum/account/balance/" + ethadd
    res = requests.get(balance_url, headers={"x-api-key":InputAPI})
    res = res.json() 
    balanceeth = float(res['balance'])
    return balanceeth
    
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


filename ='eth.txt'
with open(filename) as f:
    line_count = 0
    for line in f:
        line != "\n"
        line_count += 1
eth_list = [line.split()[0].lower() for line in open(filename,'r')]
eth_list = set(eth_list)

prompt= '''
    ************************ Main Menu Mizogg's ETH Tools *******************
    *                       Single Check Tools                              *
    *    Option 1.ETH Address with Blance Check      [Internet required]= 1 *
    *    Option 2.Hexadecimal to Decimal (HEX 2 DEC) [Internet required]= 2 *
    *    Option 3.Decimal to Hexadecimal (DEC 2 HEX) [Internet required]= 3 *
    *    Option 4.Mnemonic Words to dec and hex      [Internet required]= 4 *
    *                    Generators & Multi Check Tools                     *
    *                                                                       *
    *    Option 5.Mnemonic Words Generator Random Choice [Offline]  = 5     *
    *    Option 6.Mnemonic Words Generator Random Choice [ONLINE]   = 6     *
    *                                                                       *
    ************** Main Menu Mizogg's ETH Tools made in Python **************

Type You Choice Here Enter 1-6 : 
'''
InputAPI = str(input('Tools Need tatum.io API Key to run Type Here : '))
#InputAPI = '????????-????-????-????-????????????'
while True:
    data = []
    count=0
    total= 0
    start=int(input(prompt))
    if start == 1:
        print ('Ethereum Address Balance and Info Check Tool')
        ethadd = str(input('Enter Your ETH Address Here : '))
        print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
        time.sleep(3)
        
    elif start == 2:
        print('Hexadecimal to Decimal Tool')
        HEX = str(input('Enter Your Hexadecimal HEX Here : '))
        dec = int(HEX, 16)
        length = len(bin(dec))
        length -=2
        PRIVATE_KEY = "%064x" % dec
        hdwallet: HDWallet = HDWallet(symbol=SYMBOL)
        hdwallet.from_private_key(private_key=PRIVATE_KEY)
        ethadd = hdwallet.p2pkh_address()
        print('\nHexadecimal = ',HEX, '\nTo Decimal = ', dec, '  bits ', length)
        print("Cryptocurrency:", hdwallet.cryptocurrency())
        print("Symbol:", hdwallet.symbol())
        print("Network:", hdwallet.network())
        print("Uncompressed:", hdwallet.uncompressed())
        print("Compressed:", hdwallet.compressed())
        print("Private Key:", hdwallet.private_key())
        print("Public Key:", hdwallet.public_key())
        print("Finger Print:", hdwallet.finger_print())
        print("Hash:", hdwallet.hash())
        print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
        time.sleep(3)
    elif start == 3:
        print('Decimal to Hexadecimal Tool')
        dec = int(input('Enter Your Decimal DEC Here : '))
        HEX = "%064x" % dec
        length = len(bin(dec))
        length -=2
        hdwallet: HDWallet = HDWallet(symbol=SYMBOL)
        hdwallet.from_private_key(private_key=HEX)
        ethadd = hdwallet.p2pkh_address()
        print('\nDecimal = ', dec, '  bits ', length, '\nTo Hexadecimal = ', HEX)
        print("Cryptocurrency:", hdwallet.cryptocurrency())
        print("Symbol:", hdwallet.symbol())
        print("Network:", hdwallet.network())
        print("Uncompressed:", hdwallet.uncompressed())
        print("Compressed:", hdwallet.compressed())
        print("Private Key:", hdwallet.private_key())
        print("Public Key:", hdwallet.public_key())
        print("Finger Print:", hdwallet.finger_print())
        print("Hash:", hdwallet.hash())
        print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
        time.sleep(3)
    elif start ==4:
        promptword= '''
    ************************* Mnemonic Words 12/15/18/21/24 tool ************************* 
    *                                                                                    *
    *    1-OWN WORDS to DEC & HEX with Balance Check [Internet required]                 *
    *    2-Generated WORDS to DEC & HEX with Balance Check [Internet required]           *
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
            ethadd = bip44_hdwallet.address()
            HEX = bip44_hdwallet.private_key()
            dec = int(bip44_hdwallet.private_key(), 16)
            length = len(bin(dec))
            length -=2
            print('\nmnemonic_words  : ', mnemonic_words)
            print('\nPrivatekey (dec): ', dec, '  bits ', length, '\nPrivatekey (hex): ', HEX)
            print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
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
            ethadd = bip44_hdwallet.address()
            HEX = bip44_hdwallet.private_key()
            dec = int(bip44_hdwallet.private_key(), 16)
            length = len(bin(dec))
            length -=2
            print('\nmnemonic_words  : ', mnemonic_words)
            print('\nPrivatekey (dec): ', dec, '  bits ', length, '\nPrivatekey (hex): ', HEX)
            print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
            time.sleep(3)
            
        
    elif start ==5:
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
                if address in eth_list:
                    print('\nMatch Found')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    print('Derivation Path : ', target_wallet['path'], ' : ETH Address : ', target_wallet['address'])
                    print('Privatekey  : ', target_wallet['privatekey'])
                    print('Privatekey DEC : ', target_wallet['privatedec'])
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey : {target_wallet['privatekey']}
                        Public Address ETH:  {target_wallet['address']}
                        """)
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
    elif start ==6:
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
                ethadd = target_wallet['address']
                time.sleep(0.2)
                print(f''' 
         |==============================================|======================|
         | Ethereum (ETH) Address                       |       Balance        |
         |==============================================|======================|
         | ''', ethadd, ''' |''', eth_bal(ethadd), '''                 |
         |==============================================|======================|''')
                if eth_bal(ethadd) > 0:
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey : {target_wallet['privatekey']}
                        Public Address ETH:  {target_wallet['address']}""")
                    
    else:
        print("WRONG NUMBER!!! MUST CHOSE 1 - 6 ")
