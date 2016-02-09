import os.path

INSTALLED_APPS = (
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'django_kerberos',
)
TEMPLATE_DIRS = (os.path.join(os.path.dirname(__file__), 'templates'),)
ROOT_URLCONF = 'django_kerberos.urls'
SECRET_KEY = 'xxx'
