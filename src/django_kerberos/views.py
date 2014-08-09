import kerberos

from django import http
from django.template.response import TemplateResponse
from django.contrib.auth import authenticate, login as auth_login
from django.conf import settings

from . import app_settings

def www_authenticate(request):
    response = TemplateResponse(request, 'django_kerberos/unauthorized.html', status=401)
    response['WWW-Authenticate'] = 'Negotiate'
    return response

def login(request):
    '''Try to authenticate the user using SPNEGO and Kerberos'''
    next_url = request.REQUEST.get('next') or settings.LOGIN_REDIRECT_URL
    host = app_settings.HOSTNAME or request.get_host().split(':')[0]
    service = 'HTTP@%s' % host

    if 'HTTP_AUTHORIZATION' in request.META:
        kind, authstr = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
        print authstr
        if kind == 'Negotiate':
            result, context = kerberos.authGSSServerInit(service)
            if result != 1:
                return TemplateResponse(request, 'django_kerberos/error.html')
            r = kerberos.authGSSServerStep(context, authstr)
            if r == 1:
                gssstring = kerberos.authGSSServerResponse(context)
            else:
                return www_authenticate(request)
            principal = kerberos.authGSSServerUserName(context)
            kerberos.authGSSServerClean(context)
            user = authenticate(principal=principal)
            if user:
                auth_login(request, user)
                response = http.HttpResponseRedirect(next_url)
                response['WWW-Authenticate'] = 'Negotiate %s' % gssstring
                return response
    return www_authenticate(request)
