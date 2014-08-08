import re

from . import app_settings

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

class KerberosBackend(ModelBackend):
    def authenticate(self, principal=None):
        '''Match principal username with Django user model username'''
        if not principal:
            return
        User = get_user_model()
        username = principal.split('@')[0]
        username_field = getattr(User, 'USERNAME_FIELD', 'username')
        kwargs = {username_field: username}
        if app_settings.BACKEND_CREATE:
            user, created = User.objects.get_or_create(**kwargs)
        else:
            try:
                user = User.objects.get(**kwargs)
            except User.DoesNotExist:
                return
        # basic authorization
        if app_settings.BACKEND_ADMIN_REGEXP:
            if re.match(app_settings.BACKEND_ADMIN_REGEXP, username):
                if not user.is_staff or not user.is_superuser:
                    user.is_staff = True
                    user.is_superuser = True
                    user.save()
        return user



