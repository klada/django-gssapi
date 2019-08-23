# django-gssapi - SPNEGO/Kerberos authentication for Django applications
# Copyright (C) 2014-2019 Entr'ouvert
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import unicode_literals

import logging

from django import http
from django.conf import settings
from django.utils.http import is_safe_url
from django.views.generic.base import View

from django.contrib.auth import login as auth_login, REDIRECT_FIELD_NAME

from . import utils

logger = logging.getLogger('django_kerberos')


class NegotiateFailed(Exception):
    pass


class LoginView(View):
    redirect_field_name = REDIRECT_FIELD_NAME

    def get_success_url_allowed_hosts(self):
        return {self.request.get_host()}

    def get_redirect_url(self):
        """Return the user-originating redirect URL if it's safe."""
        redirect_to = self.request.POST.get(
            self.redirect_field_name,
            self.request.GET.get(self.redirect_field_name, '')
        )
        url_is_safe = is_safe_url(
            url=redirect_to,
            allowed_hosts=self.get_success_url_allowed_hosts(),
            require_https=self.request.is_secure(),
        )
        return redirect_to if url_is_safe else settings.LOGIN_REDIRECT_URL

    def get_gssapi_store(self):
        return getattr(settings, 'GSSAPI_STORE', None)

    def get_gssapi_name(self):
        # force a service name, ex. :
        # server_name = 'HTTP@%s' % self.request.get_host()
        # return gssapi.Name(server_name, name_type=gssapi.NameType.hostbased_service)
        # without one, any service name in keytab will do
        return getattr(settings, 'GSSAPI_NAME', None)

    def challenge(self):
        '''Send negotiate challenge'''
        return utils.challenge_response()

    def success(self, user):
        '''Do something with the user we found'''
        auth_login(self.request, user)
        return http.HttpResponseRedirect(self.get_redirect_url())

    def negotiate(self):
        '''Try to authenticate the user using SPNEGO'''

        try:
            user, gss_name, token = utils.negotiate_and_auth(
                self.request,
                name=self.get_gssapi_name(),
                store=self.get_gssapi_store())
        except utils.NegotiateContinue as e:
            token = e.token

        if user is None:
            response = self.challenge()
        else:
            logger.debug('GSSAPI found user %s for name %s', user, gss_name)
            response = self.success(user)

        utils.response_add_www_authenticate(response, token)
        return response

    def get(self, request, *args, **kwargs):
        return self.negotiate()

    def post(self, request, *args, **kwargs):
        return self.negotiate()

login = LoginView.as_view()
