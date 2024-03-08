"""import base64
import binascii
from codecs import decode, encode
from http import client
import string
import sys
from time import sleep"""
from scapy.all import *
"""import scapy.layers.tls.crypto.prf as prf
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode
from Crypto.Util.Padding import unpad, pad"""

premaster:bytes
symmetric_key:bytes
application_data=[]
client_rand:bytes
server_rand:bytes

def decrypt_data(enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv )
        return cipher.decrypt( enc[16:] )

def parse_pkts(filename:string):
    load_layer("tls")
    pkts=PacketList(rdpcap("best_game.pcap"))
    tls_packets=[]
    i=0
    pre_master=b''
    for pkt in pkts[TLS]:
        a=pkt.show(dump=True)
        
        tls_packets.append(a[a.index("###[ TLS ]###"):])  #binascii.b2a_hex(x)
        print(a)
        print("\n\n---------------------------------------------")
        if tls_packets[i].find("random_bytes")!=-1:
            if pkt.getlayer(TLSClientHello):
                global client_rand
                client_rand=pkt[TLSClientHello].random_bytes
                
            else:
                global server_rand
                server_rand=pkt[TLSServerHello].random_bytes
                
            #print(tls_packets[i])
            #print("\n\n-------------------------")
            pass
        elif tls_packets[i].find("client_key_exchange")!=-1:
            print(len(pkt.load))
        """elif tls_packets[i].find("application_data")!=-1:
            try:
                application_data.append(pkt[TLSApplicationData].data)
            except IndexError:
                print("hhhhhhhhhhhhhhhhh")
                pass"""
            #print(pkt[TLSApplicationData].data)
            #print("\n\n--------------------")
        i+=1
    return pre_master

def decrypt_premaster(enc_pre_master=None):
    
    rsa_key = RSA.import_key(open('server.key', "rb").read())
    #print(rsa_key.export_key())
    #print(rsa_key.size_in_bits())
    cipher = PKCS1_v1_5.new(rsa_key)
    decrypted_pre = cipher.decrypt(enc_pre_master,"")
    return decrypted_pre


def main():
    load_layer("tls")

    packets = rdpcap("best_game.pcap")
    
    client_hello = TLS(raw(packets[3][TLS]))
    server_hello = TLS(raw(packets[5][TLS]), tls_session=client_hello.tls_session.mirror())
    server_hello.tls_session.server_rsa_key=PrivKey("server.key")
    client_exchange = TLS(raw(packets[7][TLS]), tls_session=server_hello.tls_session.mirror())
    new_ticket = TLS(raw(packets[9][TLS]), tls_session=client_exchange.tls_session.mirror())
    data = packets[11][TLS].show()
    appdata = TLS(raw(packets[11][TLS]), tls_session=new_ticket.tls_session.mirror())
    appdata.show()
    appdata2 = TLS(raw(packets[13][TLS]), tls_session=new_ticket.tls_session.mirror())
    appdata2.show()
    #secret=new_ticket.tls_session.master_secret
    #s_rand=new_ticket.tls_session.server_random
    #c_rand=new_ticket.tls_session.client_random
    #padding=appdata2.pad
    #iv=appdata2.iv
    #data=appdata2[TLSApplicationData].data
    #print(len(appdata2))
    #print(pad)
    #print(len(packets[13][Raw]))
    #obj=prf.PRF(hash_name="SHA1",tls_version=0x0303)
    #symmetric_key=obj.derive_key_block(master_secret=secret, server_random=s_rand, client_random=c_rand, req_len=16)
    #cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    #print(decode(cipher.decrypt(pad(data,AES.block_size))))
    #new_ticket.tls_session.compute_ms_and_derive_keys() 
    #print(packets[11][TLS].show())
    #print((packets[11][TLS].show()))
    #appdata = TLS(raw(packets[11][TLS]), tls_session=new_ticket.tls_session.mirror())
    #appdata2= TLS(raw(packets[14][TLS]),tls_session=appdata.tls_session.mirror())
    
    #data=TLS(raw(packets[11][TLS]), tls_session = client_exchange.tls_session.mirror())
    #print(type(client_hello.tls_session))

    #http_query = TLS(raw(packets[11][TLS]), tls_session=server_hello.tls_session.mirror())
    #http_query.show()
    #premaster=parse_pkts("best_game.pcap")
    #decrypted_pre=decrypt_premaster(premaster[2:])
    #print(len(decrypted_pre))
    #print(decrypted_pre)
    
    #symmetric_key=obj.derive_key_block(master_secret=master_secret, server_random=server_rand, client_random=client_rand, req_len=64)
    #print(keys)
    #decrypt_data(application_data, decrypted_pre, server_rand, client_rand)
    #print(symmetric_key)

    #print(len(symmetric_key))

def decrypt_data(app_data:list, decrypted_pre, server_random, client_random):
    obj=prf.PRF(hash_name="SHA1",tls_version=0x0303)
    master_secret=obj.compute_master_secret(decrypted_pre, client_rand, server_rand)
    
    symmetric_key=obj.derive_key_block(master_secret=master_secret, server_random=server_rand, client_random=client_rand, req_len=64)
    cipher=AES.new(symmetric_key[0:16], AES.MODE_CBC)

    #cipher,iv=_create_cbc_cipher()
    cat_data=b''
    for data in app_data:
        cat_data+=data
        #print(data)
        #print(cipher.decrypt(data))
    #print("\n--------------------------------------------\n")
    #print(cat_data)
    

def list_contains(container:list, key:string):
    for i in range(len(container)):
        if container[i] == key:
            return True
    return False

if __name__ == '__main__':
    main()