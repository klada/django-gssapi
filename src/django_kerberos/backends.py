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

import re
import logging

import six

from django.core.exceptions import ImproperlyConfigured
from django.utils.encoding import force_bytes

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

import kerberos

from . import app_settings


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

    def authenticate(self, request=None, principal=None):
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
            raise ImproperlyConfigured('Kerberos password backend needs the '
                                       'setting KERBEROS_SERVICE_PRINCIPAL to be'
                                       ' set')
        return app_settings.SERVICE_PRINCIPAL

    def authenticate(self, request=None, username=None, password=None):
        '''Verify username and password using Kerberos'''
        if not username:
            return

        kerb_principal = principal = self.principal_from_username(username)
        kerb_password = password

        if six.PY2:
            kerb_principal = force_bytes(kerb_principal)
            kerb_password = force_bytes(kerb_principal)

        try:
            if not kerberos.checkPassword(kerb_principal, kerb_password,
                                          self.service_principal(),
                                          self.default_realm()):
                return
        except kerberos.KrbError as e:
            logging.getLogger(__name__).error(
                'password validation for principal %r failed %s', principal, e)
            return
        else:
            if principal and self.authorize_principal(principal):
                user = self.lookup_user(principal)
                if self.keep_password():
                    user.set_password(password)
                return user
