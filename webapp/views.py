from django.http import HttpResponseRedirect
from django.http import HttpResponse
from django.shortcuts import render_to_response
from settings import *

from healthvaultlib.healthvault import HealthVaultConn

def index(request):
  loginurl 	= HV_SHELL_URL+"/redirect.aspx?target=AUTH&targetqs=?appid="+HV_APPID+"%26redirect="+APP_ACTION_URL
  template_values = {'loginurl':loginurl,
  	'HV_APPID':HV_APPID,
	'APP_ACTION_URL':APP_ACTION_URL,
	'HV_SHELL_URL':HV_SHELL_URL,
	'HV_SERVICE_SERVER': HV_SERVICE_SERVER,
	'APP_PUBLIC_KEY': APP_PUBLIC_KEY[:20]+"...",
	'APP_PRIVATE_KEY':APP_PRIVATE_KEY[:20]+"...",
	'APP_THUMBPRINT':APP_THUMBPRINT[:20]+"...",
  	}
  return render_to_response('index.html', template_values)

def mvaultaction(request):
	 target 	= ''
	 if request.GET.has_key('target'):
	 	target  = request.GET['target']
	 else:
		return HttpResponse('')
	 if target == "Home":
		return HttpResponseRedirect('/')
	 if target == "AppAuthSuccess":
		return HttpResponseRedirect('/mvaultentry?'+request.META['QUERY_STRING'])
	 if target == "ServiceAgreement":
		return HttpResponseRedirect('/YouAPPTermsOfService.html')
	 if target == "Help":
		return HttpResponseRedirect('/YourAppHelp.html')
	 if target == "Privacy":
		return HttpResponseRedirect('/YourAppPrivacy.html')
	 if target == "AppAuthReject":
		return HttpResponseRedirect('/')
	 if target == "SelectedRecordChanged":
		return HttpResponseRedirect('/')
	 if target == "ShareRecordSuccess":
		return HttpResponseRedirect('/')
	 if target == "ShareRecordFailed":
		return HttpResponseRedirect('/')
	 if target == "SignOut":
		return HttpResponseRedirect('/')
	 return HttpResponse('')

def mvaultentry(request):
	target  = request.GET['target']
	wctoken = ""
	if target == "AppAuthSuccess":
		wctoken = request.GET['wctoken']
	else:
		return HttpResponse("cannot get wctoken")

	hvconn	= HealthVaultConn(wctoken)
	demo	= hvconn.getBasicDemographicInfo()	
	template_values = {'basicdemographic':demo}
	return render_to_response('hvdata.html',template_values)

