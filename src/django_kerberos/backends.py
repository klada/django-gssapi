import re

import logging

from . import app_settings

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

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

    def lookup_user(self, principal):
        '''Find the user model linked to this principal'''
        User = get_user_model()
        username_field = getattr(User, 'USERNAME_FIELD', 'username')
        username = self.username_from_principal(principal)
        kwargs = {username_field: username}
        if app_settings.BACKEND_CREATE:
            user, created = User.objects.get_or_create(**kwargs)
        else:
            try:
                user = User.objects.get(**kwargs)
            except User.DoesNotExist:
                return
        self.provision_user(principal, user)
        return user


    def authenticate(self, principal=None):
        if principal and self.authorize_principal(principal):
            return self.lookup_user(principal)



