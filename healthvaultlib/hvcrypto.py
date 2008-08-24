#The MIT License
#Copyright (c) 2008 Applied Informatics, Inc.

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in
#all copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#THE SOFTWARE.

import base64
import hashlib
from Crypto.PublicKey import RSA
from binascii import a2b_hex, b2a_hex
from settings import *

class HVCrypto(object):
	em  		= None
	private_key	= None
	def __init__(self):
		public_key_long 	= long(APP_PUBLIC_KEY,16)
  		private_key_long 	= long(APP_PRIVATE_KEY,16)
  		rsa_n_bit_length 	= 2048 
  		self.em 		= (rsa_n_bit_length + 7)/8
  		#['n', 'e', 'd', 'p', 'q', 'u']
		exponent = 65537
  		self.private_key = RSA.construct((public_key_long, exponent, private_key_long))

	def i2osp(self,long_integer, block_size ):
		'Convert a long integer into an octet string.'
		hex_string = '%X' % long_integer
		if len( hex_string ) > 2 * block_size:
			raise ValueError( 'integer %i too large to encode in %i octets' % ( long_integer, block_size ) )
		return a2b_hex( hex_string.zfill( 2 * block_size ) )

	def os2ip(self,octet_string ):
	  'Convert an octet string to a long integer.'
	  return long( b2a_hex( octet_string ), 16 )

	def pad_rsa(self,hashed_msg):        
		#this is for PKCS#1 padding        
		prefix          = '\x30\x21\x30\x09\x06\x05\x2b\x0E\x03\x02\x1A\x05\x00\x04\x14'
		padlen          =  self.em - len(prefix) - len(hashed_msg) - 3
		padding         = ''.join(['\xff' for x in range(padlen)])
		pad_result      = ''.join(['\x00\x01', padding, '\x00', prefix, hashed_msg])
		return pad_result

	def sign(self,data2sign):
	   hashed_msg    = hashlib.sha1(data2sign).digest()
	   pad_result    = self.pad_rsa(hashed_msg)
	   sig           = self.private_key.sign(self.os2ip(pad_result), None)[0]
	   bsig          = base64.encodestring(self.i2osp(sig,self.em))
	   return bsig

