import logging

import kerberos

from django import http
from django.template.response import TemplateResponse
from django.conf import settings
from django.views.generic.base import View

from django.contrib.auth import authenticate, login as auth_login

from . import app_settings


class NegotiateView(View):
    NEXT_URL_FIELD = 'next'
    unauthorized_template_name = 'django_kerberos/unauthorized.html'
    error_template_name = 'django_kerberos/error.html'

    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger(__name__)
        super(NegotiateView, self).__init__(*args, **kwargs)

    def challenge(self, request, *args, **kwargs):
        '''Send negotiate challenge'''
        response = TemplateResponse(request, self.unauthorized_template_name, status=401)
        response['WWW-Authenticate'] = 'Negotiate'
        return response

    def host(self, request):
        return app_settings.HOSTNAME or request.get_host().split(':')[0]

    def principal_valid(self, request, *args, **kwargs):
        '''Do something with the principal we received'''
        user = authenticate(principal=self.principal)
        next_url = request.REQUEST.get(self.NEXT_URL_FIELD)
        if user:
            return self.user_found(request, user, *args, **kwargs)
        if request.is_ajax() and not next_url:
            return self.user_not_found(request, *args, **kwargs)

    def user_found(self, request, user, *args, **kwargs):
        auth_login(request, user)
        next_url = request.REQUEST.get(self.NEXT_URL_FIELD)
        if request.is_ajax() and not next_url:
            return http.HttpResponse('true', content_type='application/json')
        else:
            next_url = next_url or settings.LOGIN_REDIRECT_URL
            response = http.HttpResponseRedirect(next_url)
            return response

    def user_not_found(self, request, *wargs, **kwargs):
        return http.HttpResponse('false', content_type='application/json')

    def negotiate(self, request, *args, **kwargs):
        '''Try to authenticate the user using SPNEGO and Kerberos'''

        if 'HTTP_AUTHORIZATION' in request.META:
            kind, authstr = request.META['HTTP_AUTHORIZATION'].split(' ', 1)
            if kind == 'Negotiate':
                service = 'HTTP@%s' % self.host(request)
                self.logger.debug(u'using service name %s', service)
                self.logger.debug(u'Negotiate authstr %r', authstr)
                try:
                    result, context = kerberos.authGSSServerInit(service)
                except kerberos.KrbError, e:
                    self.logger.warning(u'exception during authGSSServerInit: %s, certainly a '
                                        u'keytab problem', e)
                    details = (u'exception during authGSSServerInit: %s, certainly a '
                               u'keytab problem' % e)
                    return TemplateResponse(request, self.error_template_name,
                                            context={'details': details}, status=500)
                # ensure context is finalized
                try:
                    if result != 1:
                        self.logger.warning(u'authGSSServerInit result is non-zero: %s', result)
                        details = u'authGSSServerInit result is non-zero: %s' % result
                        return TemplateResponse(request, self.error_template_name,
                                                context={'details': details}, status=500)
                    try:
                        r = kerberos.authGSSServerStep(context, authstr)
                    except kerberos.KrbError, e:
                        self.logger.warning(u'exception during authGSSServerStep: %s', e)
                        details = u'exception during authGSSServerStep: %s' % e
                        return TemplateResponse(request, self.error_template_name,
                                                context={'details': details}, status=500)
                    if r == 1:
                        gssstring = kerberos.authGSSServerResponse(context)
                    else:
                        return self.challenge(request, *args, **kwargs)
                    try:
                        self.principal = kerberos.authGSSServerUserName(context)
                    except kerberos.KrbError, e:
                        self.logger.warning(u'exception during authGSSServerUserName: %s', e)
                        details = u'exception during authGSSServerUserName: %s' % e
                        return TemplateResponse(request, self.error_template_name,
                                                context={'details': details}, status=500)
                finally:
                    kerberos.authGSSServerClean(context)
                response = self.principal_valid(request, *args, **kwargs)
                if response:
                    response['WWW-Authenticate'] = 'Negotiate %s' % gssstring
                    return response
        return self.challenge(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return self.negotiate(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.negotiate(request, *args, **kwargs)

login = NegotiateView.as_view()
