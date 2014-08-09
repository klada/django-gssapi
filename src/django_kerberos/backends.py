import re
import logging

from . import app_settings

from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_bytes

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

import kerberos

class KerberosBackend(ModelBackend):
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def username_from_principal(self, principal):
        '''Make a username from a principal name'''
        username, domain = principal.rsplit('@', 1)
        return u'{0}@{1}'.format(username, domain.lower())

    def authorize_principal(self, principal):
        '''Is this principal authorized to login ?'''
        return True

    def provision_user(self, principal, user):
        '''Modify user based on information we can retrieve on this principal'''
        if app_settings.BACKEND_ADMIN_REGEXP:
            if re.match(app_settings.BACKEND_ADMIN_REGEXP, principal):
                if not user.is_staff or not user.is_superuser:
                    self.logger.info('giving superuser power to principal %r', principal)
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()

    def should_create_user(self):
        '''Should we create users for new principals ?'''
        return app_settings.BACKEND_CREATE

    def lookup_user(self, principal):
        '''Find the user model linked to this principal'''
        User = get_user_model()
        username_field = getattr(User, 'USERNAME_FIELD', 'username')
        username = self.username_from_principal(principal)
        kwargs = {username_field: username}
        if self.should_create_user():
            user, created = User.objects.get_or_create(**kwargs)
            if created:
                user.set_unusable_password()
                user.save()
        else:
            try:
                user = User.objects.get(**kwargs)
            except User.DoesNotExist:
                return
        self.provision_user(principal, user)
        return user


    def authenticate(self, principal=None, **kwargs):
        if principal and self.authorize_principal(principal):
            return self.lookup_user(principal)


class KerberosPasswordBackend(KerberosBackend):
    def default_realm(self):
        '''Default realm for usernames without a realm'''
        return app_settings.DEFAULT_REALM

    def principal_from_username(self, username):
        realm = self.default_realm()
        if '@' not in username and realm:
            username = u'%s@%s' % (username, realm)
        return username

    def keep_password(self):
        '''Do we save a password hash ?'''
        return app_settings.KEEP_PASSWORD

    def service_principal(self):
        '''Service principal for checking password'''
        if not app_settings.SERVICE_PRINCIPAL:
            raise ImproperlyConfigured('Kerberos password backend needs '
                    'the setting KERBEROS_SERVICE_PRINCIPAL to be '
                    'set')
        return app_settings.SERVICE_PRINCIPAL

    def authenticate(self, username=None, password=None, **kwargs):
        '''Verify username and password using Kerberos'''
        if not username:
            return

        principal = force_bytes(self.principal_from_username(username))
        password = force_bytes(password)

        try:
            if not kerberos.checkPassword(principal, password,
                    self.service_principal(), self.default_realm()):
                return
        except kerberos.KrbError, e:
            logging.getLogger(__name__).error('password validation'
                    'for principal %r failed %s', principal, e)
            return
        else:
            if principal and self.authorize_principal(principal):
                user = self.lookup_user(principal)
                if self.keep_password():
                    user.set_password(password)
                return user
