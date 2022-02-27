#!/usr/bin/env python3

from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.derivations import BIP44Derivation
from hdwallet.utils import generate_mnemonic
from typing import Optional
import random, requests

api1="?apiKey=freekey"
api2="?apiKey=freekey"

def get_TXS(ethadd):
    mylist = [str(api1), str(api2)]
    apikeys=random.choice(mylist)
    blocs=requests.get("https://api.ethplorer.io/getAddressInfo/" + ethadd +apikeys)
    ress = blocs.json()
    TXS = dict(ress)["countTxs"]
    return TXS

def data_wallet():
    for address_index in range(divs):
        bip44_derivation: BIP44Derivation = BIP44Derivation(
            cryptocurrency=EthereumMainnet, account=0, change=False, address=address_index
        )
        bip44_hdwallet.from_path(path=bip44_derivation)
        data.append({
                'path': bip44_hdwallet.path(),
                'address': bip44_hdwallet.address(),
                'privatekey': bip44_hdwallet.private_key(),
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
    *    Option 1.ETH Address with TXS Check                       =  1     *
    *    Option 2.Hexadecimal to Decimal (HEX 2 DEC)     [Offline] =  2     *
    *    Option 3.Decimal to Hexadecimal (DEC 2 HEX)     [Offline] =  3     *
    *                                                                       *
    *                    Generators & Multi Check Tools                     *
    *                                                                       *
    *    Option 4.Mnemonic Words Generator Random Choice [Offline]  = 4     *    
    *                                                                       *
    *               Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4            *
    ************** Main Menu Mizogg's ETH Tools made in Python **************

Type You Choice Here Enter 1-4 : 
'''

while True:
    data = []
    mylist = []
    count=0
    total= 0
    start=int(input(prompt))
    if start == 1:
        print ('Address Transaction Check Tool')
        ethadd = str(input('Enter Your ETH Address Here : '))
        print ('\nETH Address = ', ethadd, '    Transations = ', get_TXS(ethadd), ' TXS')
    elif start == 2:
        print('Hexadecimal to Decimal Tool')
        HEX = str(input('Enter Your Hexadecimal HEX Here : '))
        dec = int(HEX, 16)
        print('\nHexadecimal = ',HEX, '\nTo Decimal = ', dec)
    elif start == 3:
        print('Decimal to Hexadecimal Tool')
        dec = int(input('Enter Your Decimal DEC Here : '))
        HEX = "%064x" % dec       
    elif start ==4:
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
        display = int(input('1=Full Display (Slower) 2=Slient Mode (Faster) : '))
        while True:
            data=[]
            count += 1
            total += divs
            #MNEMONIC: str = 'manual resource salon small metal twist cloth curtain into banner steel bonus'
            MNEMONIC: str = generate_mnemonic(language="english", strength=s1)
            PASSPHRASE: Optional[str] = None
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(
                mnemonic=MNEMONIC, language="english", passphrase=PASSPHRASE
            )
            bip44_hdwallet.clean_derivation()
            mnemonic_words = bip44_hdwallet.mnemonic()
            data_wallet()
            for target_wallet in data:
                address = target_wallet['address'].lower()
                if address in eth_list:
                    print('\nMatch Found')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    print('Derivation Path : ', target_wallet['path'], ' : ETH Address : ', target_wallet['address'])
                    print('Privatekey  : 0x', target_wallet['privatekey'])
                    with open("winner.txt", "a") as f:
                        f.write(f"""\nMnemonic_words:  {mnemonic_words}
                        Derivation Path:  {target_wallet['path']}
                        Privatekey :  0x{target_wallet['privatekey']}
                        Public Address ETH:  {target_wallet['address']}
                        =====Made by mizogg.co.uk Donations 3GCypcW8LWzNfJEsTvcFwUny3ygPzpTfL4 =====""")
            else:
                if display == 1:
                    print(' [' + str(count) + '] ------------------------')
                    print('Total Checked [' + str(total) + '] ')
                    print('\nmnemonic_words  : ', mnemonic_words)
                    for bad_wallet in data:
                        print('Derivation Path : ', bad_wallet['path'], ' : ETH Address : ', bad_wallet['address'])
                        print('Privatekey : 0x', bad_wallet['privatekey'])
                elif display == 2:
                    print(' [' + str(count) + '] ------', 'Total Checked [' + str(total) + '] ', end='\r')
    else:
        print("WRONG NUMBER!!! MUST CHOSE 1 - 4 ")