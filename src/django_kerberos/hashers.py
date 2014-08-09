import logging
import kerberos

from django.core.exceptions import ImproperlyConfigured
from django.contrib.auth.hashers import BasePasswordHasher
from django.utils.encoding import force_bytes

from . import app_settings

class KerberosHasher(BasePasswordHasher):
    '''A pseudo hasher which just validate that the given password
       match a given Kerberos identity'''
    algorithm = 'kerberos'

    def verify(self, password, encoded):
        algorithm, principal = encoded.split('$', 2)
        assert algorithm == self.algorithm
        principal = force_bytes(principal)
        password = force_bytes(principal)
        if not app_settings.SERVICE_PRINCIPAL:
            raise ImproperlyConfigured('Kerberos pseudo password hasher needs '
                    'the setting KERBEROS_SERVICE_PRINCIPAL to be '
                    'set')
        try:
            return kerberos.checkPassword(principal, password,
                    app_settings.SERVICE_PRINCIPAL)
        except kerberos.KrbError, e:
            logging.getLogger(__name__).error('password validation'
                    'for principal %r failed %s', principal, e)
            return False


