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
import warnings


from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes

import gssapi
import gssapi.exceptions
import gssapi.raw as gb


logger = logging.getLogger('django_gssapi')


class GSSAPIBackend(object):
    def authenticate(self, request, gssapi_name):
        warnings.warn('example backend do not use in production!')
        # pylint: disable=invalid-name
        User = get_user_model()
        try:
            user = User.objects.get(username=str(gssapi_name))
        except User.DoesNotExist:
            logger.debug('GSSAPI no user found for name %s', gssapi_name)
        else:
            if user.is_active:
                return user
        return None


class KerberosPasswordBackend(object):
    def principal_from_user(self, user):
        return user.username

    def authenticate(self, request, username=None, password=None, **kwargs):
        '''Verify username and password using Kerberos'''
        warnings.warn('Kerberos: example backend do not use in production!')

        # pylint: disable=invalid-name
        User = get_user_model()

        if username is None:
            username = kwargs.get(User.USERNAME_FIELD)
        try:
            user = User._default_manager.get_by_natural_key(username)
        except User.DoesNotExist:
            logger.debug('Kerberos: no user for username %s', username)
            return None
        else:
            if not user.is_active:
                return None

        principal = self.principal_from_user(user)

        try:
            name = gb.import_name(force_bytes(principal), gb.NameType.kerberos_principal)
            if gb.acquire_cred_with_password(name, force_bytes(password)):
                if not user.check_password(password):
                    user.set_password(password)
                    user.save()
                return user
        except gssapi.exceptions.GSSError as e:
            logger.debug('Kerberos: password check failed  for principal %s: %s', principal, e)
        return None
