import sys

class AppSettings(object):
    __PREFIX = 'KERBEROS_'
    __DEFAULTS = {
            'HOSTNAME': None,
            'KEYTAB': None,
            'BACKEND_CREATE': False,
            'BACKEND_ADMIN_REGEXP': None,
    }

    def __getattr__(self, name):
        from django.conf import settings
        if name not in self.__DEFAULTS:
            raise AttributeError
        return getattr(settings, self.__PREFIX + name, self.__DEFAULTS[name])

app_settings = AppSettings()
app_settings.__name__ = __name__
sys.modules[__name__] = app_settings
