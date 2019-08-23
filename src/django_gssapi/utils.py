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

import base64
import logging

import gssapi
import gssapi.exceptions

from django import http
from django.contrib.auth import authenticate

logger = logging.getLogger('django_kerberos')


class NegotiateContinue(Exception):
    def __init__(self, token):
        super(NegotiateContinue, self).__init__()
        self.token = token


def negotiate(request, name=None, store=None):
    '''Try to authenticate the user using SPNEGO and Kerberos'''

    if name:
        logger.debug(u'GSSAPI negotiate using name %s', name)

    try:
        server_creds = gssapi.Credentials(usage='accept', name=name, store=store)
    except gssapi.exceptions.GSSError as e:
        logging.debug('GSSAPI credentials failure: %s', e)
        return None, None

    if not request.META.get('HTTP_AUTHORIZATION', '').startswith('Negotiate '):
        return None, None

    authstr = request.META['HTTP_AUTHORIZATION'][10:]
    try:
        in_token = base64.b64decode(authstr)
    except ValueError:
        return None, None

    server_ctx = gssapi.SecurityContext(creds=server_creds, usage='accept')
    try:
        out_token = server_ctx.step(in_token)
    except gssapi.exceptions.GSSError as e:
        logging.debug('GSSAPI security context failure: %s', e)
    if not server_ctx.complete:
        raise NegotiateContinue(out_token)

    return server_ctx.initiator_name, out_token


def negotiate_and_auth(request, name=None, store=None):
    gssapi_name, token = negotiate(request, name=name, store=store)

    if gssapi_name is None:
        return None, None, token

    return authenticate(gssapi_name=gssapi_name), gssapi_name, token


def challenge_response():
    '''Send negotiate challenge'''
    response = http.HttpResponse('GSSAPI authentication failed', status=401)
    response_add_www_authenticate(response)
    return response


def authenticate_header(token=None):
    return 'Negotiate%s' % (' ' + base64.b64encode(token).decode('ascii') if token else '')


def response_add_www_authenticate(response, token=None):
    response['WWW-Authenticate'] = authenticate_header(token)
