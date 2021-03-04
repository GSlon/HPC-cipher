import pathlib
from Converter import Converter
from CiphModes import *


blocksize = 128  # in bits
key = '0x112'   # hex str
spice = 0x4957df9f02329f2d07289bb61a440e059f9c5dcb93048b5686208a26403c5e7f99ed0051cdb0d7bb8f0c6e4962e43023a0b02b363ffa0b53abf6d3f4f848f5e9 # int

file = 'lk.pdf'
fileW = 'temp.ctxt'
fileW2 = 'lkDec4.pdf'
path = str(pathlib.Path().absolute()) + '/examples/'

data = b''
with open(path+file, 'rb') as f:
    data = f.read()

temp = OFB_encrypt(Converter.bytes_to_hex_list(data, blocksize), key, spice, '0xaf01ee9212883311af01ee9212883311')

with open(path+fileW, 'wb') as f:
    f.write(Converter.hex_to_bytes(temp, useLastBlock=False))

with open(path+fileW, 'rb') as f:
    data = f.read()

temp = OFB_decrypt(Converter.bytes_to_hex_list(data, blocksize, useLastBlock=False), key, spice, '0xaf01ee9212883311af01ee9212883311')

with open(path+fileW2, 'wb') as f:
    f.write(Converter.hex_to_bytes(temp))

    