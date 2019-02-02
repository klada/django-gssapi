# django-kerberos - SPNEGO/Kerberos authentication for Django applications
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

import logging

from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_bytes

from django.contrib.auth.hashers import BasePasswordHasher

import kerberos

from . import app_settings


class KerberosHasher(BasePasswordHasher):
    '''A pseudo hasher which just validate that the given password
       match a given Kerberos identity'''
    algorithm = 'kerberos'

    def default_realm(self):
        '''Default realm for usernames without a realm'''
        return app_settings.DEFAULT_REALM

    def service_principal(self):
        if not app_settings.SERVICE_PRINCIPAL:
            raise ImproperlyConfigured(
                'Kerberos pseudo password hasher needs the setting '
                'KERBEROS_SERVICE_PRINCIPAL to be set')
        return app_settings.SERVICE_PRINCIPAL

    def verify(self, password, encoded):
        algorithm, principal = encoded.split('$', 2)
        assert algorithm == self.algorithm
        principal = force_bytes(principal)
        password = force_bytes(password)
        try:
            return kerberos.checkPassword(
                principal, password,
                self.service_principal(),
                self.default_realm())
        except kerberos.KrbError as e:
            logging.getLogger(__name__).error(
                'password validation for principal %r failed %s', principal, e)
            return False
