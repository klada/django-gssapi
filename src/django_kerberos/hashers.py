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
            raise ImproperlyConfigured('Kerberos pseudo password hasher needs '
                    'the setting KERBEROS_SERVICE_PRINCIPAL to be '
                    'set')
        return app_settings.SERVICE_PRINCIPAL

    def verify(self, password, encoded):
        algorithm, principal = encoded.split('$', 2)
        assert algorithm == self.algorithm
        principal = force_bytes(principal)
        password = force_bytes(password)
        try:
            return kerberos.checkPassword(principal, password,
                    self.service_principal(), self.default_realm())
        except kerberos.KrbError, e:
            logging.getLogger(__name__).error('password validation'
                    'for principal %r failed %s', principal, e)
            return False


