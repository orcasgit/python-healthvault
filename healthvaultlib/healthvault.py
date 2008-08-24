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

import cgi
import wsgiref.handlers
import os
import base64
import hashlib
import urllib
from random import randint
from xml.dom import minidom
import hmac
from django.http import HttpResponseRedirect
from django.http import HttpResponse
import httplib
from pyHealthVault.healthvaultlib.hvcrypto import HVCrypto
from settings import *

class HealthVaultConn(object):
	wctoken 	= None
	auth_token 	= None
	sharedsec	= None
	signature 	= None
	crypto		= None
	record_id	= None

	def __init__(self, wctoken):
		self.wctoken = wctoken
		crypto	 = HVCrypto()
		sharedsec   = str(randint(2**64, 2**65-1))
		self.sharedsec = sharedsec
  		sharedsec64 = base64.encodestring(sharedsec)
    		#2. create content with shared sec
  		content    = '<content><app-id>'+HV_APPID+'</app-id><shared-secret><hmac-alg algName="HMACSHA1">'+sharedsec64+'</hmac-alg></shared-secret></content>'
  		#3. create header 
  		header     = "<header><method>CreateAuthenticatedSessionToken</method><method-version>1</method-version><app-id>"+HV_APPID+"</app-id><language>en</language><country>US</country><msg-time>2008-06-21T03:13:50.750-04:00</msg-time><msg-ttl>36000</msg-ttl><version>0.0.0.1</version></header>"
		self.signature = crypto.sign(content)
		#4. create info with signed content 
		info	= '<info><auth-info><app-id>'+HV_APPID+'</app-id><credential><appserver><sig digestMethod="SHA1" sigMethod="RSA-SHA1" thumbprint="'+APP_THUMBPRINT+'">'+self.signature+'</sig>'+content+'</appserver></credential></auth-info></info>'
		payload 	= '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">'+header+info+'</wc-request:request>'
		extra_headers = {'Content-type':'text/xml'}       
		response	= self.sendRequest(payload) 
		if response.status == 200:
			auth_response = response.read()
			dom     = minidom.parseString(auth_response)
			for node in dom.getElementsByTagName("token"):
				self.auth_token = node.firstChild.nodeValue.strip()
		else:
			return "error occured at get auth token"
	
		#5 After you get the auth_token.. get the record id
		header 	= '<header><method>GetPersonInfo</method><method-version>1</method-version><auth-session><auth-token>'+self.auth_token+'</auth-token><user-auth-token>'+self.wctoken+'</user-auth-token></auth-session><language>en</language><country>US</country><msg-time>2008-06-21T03:13:50.750-04:00</msg-time><msg-ttl>36000</msg-ttl><version>0.0.0.1</version>'
		info		= '<info/>' 
		infodigest 	= base64.encodestring(hashlib.sha1(info).digest()) 
		headerinfo 	= '<info-hash><hash-data algName="SHA1">'+infodigest.strip()+'</hash-data></info-hash>'
		header = header+headerinfo+'</header>'

		hashedheader = hmac.new(sharedsec, header, hashlib.sha1)
		hashedheader64 = base64.encodestring(hashedheader.digest())
		 
		hauthxml = '<auth><hmac-data algName="HMACSHA1">'+hashedheader64.strip()+'</hmac-data></auth>'
		payload 	= '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">'+hauthxml+header+info+'</wc-request:request>'

		response	= self.sendRequest(payload) 
		if response.status == 200:
			dom     = minidom.parseString(response.read())
			for node in dom.getElementsByTagName("selected-record-id"):
				self.record_id = node.firstChild.nodeValue
		else:
			return "error occured at select record id"

	def sendRequest(self, payload):
		  conn 		= httplib.HTTPSConnection(HV_SERVICE_SERVER,443)
		  conn.putrequest('POST','/platform/wildcat.ashx')
		  conn.putheader('Content-Type','text/xml')
		  conn.putheader('Content-Length','%d' % len(payload))
		  conn.endheaders()
		  try:
			conn.send(payload)
		  except socket.error, v:
			 if v[0] == 32:      # Broken pipe
			    conn.close()
			 raise
		  return conn.getresponse()


  #HVAULT DataTypes
  #basicdemo = "bf516a61-5252-4c28-a979-27f45f62f78d"
  #ccrtype = "9c48a2b8-952c-4f5a-935d-f3292326bf54"
  #conditions = "7ea7a1f9-880b-4bd4-b593-f5660f20eda8"
  #weightmeasurementype = "3d34d87e-7fc1-4153-800f-f56592cb0d17"
 
	def getThings(self, hv_datatype):
	  #set record-id in the hearder
	  header 	= '<header><method>GetThings</method><method-version>1</method-version><record-id>'+self.record_id+'</record-id><auth-session><auth-token>'+self.auth_token+'</auth-token><user-auth-token>'+self.wctoken+'</user-auth-token></auth-session><language>en</language><country>US</country><msg-time>2008-06-21T03:13:50.750-04:00</msg-time><msg-ttl>36000</msg-ttl><version>0.0.0.1</version>'
	 
	  #QUERY INFO 
	  info		= '<info><group><filter><type-id>'+hv_datatype+'</type-id></filter><format><section>core</section><xml/></format></group></info>'

	  # INFO TO ADD WEIGHT.. change METHOD in header to PutThings
	  #info		= '<info> <thing><type-id>3d34d87e-7fc1-4153-800f-f56592cb0d17</type-id><data-xml><weight><when><date><y>2008</y><m>6</m><d>15</d></date><time><h>10</h><m>23</m><s>10</s></time></when><value><kg>60</kg><display units="lb" units-code="lb">120</display></value></weight><common/> </data-xml> </thing> </info>'
	 
	  infodigest 	= base64.encodestring(hashlib.sha1(info).digest()) 
	  headerinfo 	= '<info-hash><hash-data algName="SHA1">'+infodigest.strip()+'</hash-data></info-hash>'
	  header 	= header+headerinfo+'</header>'

	  hashedheader 	 = hmac.new(self.sharedsec, header, hashlib.sha1)
	  hashedheader64 = base64.encodestring(hashedheader.digest())
	  
	  hauthxml 	= '<auth><hmac-data algName="HMACSHA1">'+hashedheader64.strip()+'</hmac-data></auth>'
	  payload 	= '<wc-request:request xmlns:wc-request="urn:com.microsoft.wc.request">'+hauthxml+header+info+'</wc-request:request>'
	  response	= self.sendRequest(payload)
	  return response


	def getBasicDemographicInfo(self):
  	  basic_demographic_datatype	= "bf516a61-5252-4c28-a979-27f45f62f78d"
	  response	= self.getThings(basic_demographic_datatype)
	  gender 	= ''
	  dob		= ''
	  if response.status == 200:
		dom     = minidom.parseString(response.read())
		for node in dom.getElementsByTagName("gender"):
			gender = node.firstChild.nodeValue
		for node in dom.getElementsByTagName("birthyear"):
			dob = node.firstChild.nodeValue
		return gender+' '+dob
	  else:
		return 'error in getting basic demographic info'

