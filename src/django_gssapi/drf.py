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


from django.conf import settings

import rest_framework.authentication

from . import utils

__all__ = ['GSSAPIAuthentication', 'add_gssapi_mutual_auth']


class GSSAPIAuthentication(rest_framework.authentication.BaseAuthentication):
    def get_gssapi_store(self):
        return getattr(settings, 'GSSAPI_STORE', None)

    def get_gssapi_name(self):
        # force a service name, ex. :
        # server_name = 'HTTP@%s' % self.request.get_host()
        # return gssapi.Name(server_name, name_type=gssapi.NameType.hostbased_service)
        # without one, any service name in keytab will do
        return getattr(settings, 'GSSAPI_NAME', None)

    def authenticate(self, request):
        try:
            user, gss_name, token = utils.negotiate_and_auth(
                request,
                name=self.get_gssapi_name(),
                store=self.get_gssapi_store())
        except utils.NegotiateContinue as e:
            token = e.token

        if user is None:
            return None

        # DRF authentication does not allow to implement
        # natively mutual GSSAPI authentication as we
        # cannot modify the response, if needed views can retrieve the result
        # token and set it on their response
        request._drf_gssapi_token = token
        return user, gss_name

    def authenticate_header(self, request):
        return utils.authenticate_header(token=get_gssapi_token(request))


def add_gssapi_mutual_auth(request, response):
    token = get_gssapi_token(request)
    if token is not None:
        response['WWW-Authenticate'] = utils.authenticate_header(token=token)


def get_gssapi_token(request):
    return getattr(request, '_drf_gssapi_token', None)
