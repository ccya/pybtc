import sys, re
import binascii
import os
import hashlib


"""
generic helper function for python 2
"""

string_types = (str, unicode)
string_or_bytes_types = string_types
int_types = (int, float, long)

def from_int_to_byte(a):
        return chr(a)


def from_byte_to_int(a):
    return ord(a)

def safe_from_hex(s):
    return s.decode('hex')

def from_string_to_bytes(a):
    return a

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg

def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

def bin_to_b58check(inp, magicbyte=0):
	if magicbyte == 0:
	    inp = '\x00' + inp
	while magicbyte > 0:
	    inp = chr(int(magicbyte % 256)) + inp
	    magicbyte //= 256
	leadingzbytes = len(re.match('^\x00*', inp).group(0))
	checksum = bin_dbl_sha256(inp)[:4]
	return '1' * leadingzbytes + changebase(inp+checksum, 256, 58)

def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()