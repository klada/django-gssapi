#! /usr/bin/env python

''' Setup script for django-kerberos
'''

from setuptools import setup, find_packages

def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git','describe','--dirty','--match=v*'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            return result.split()[0][1:].replace('-', '.')
        else:
            return '0.0.0-%s' % len(
                    subprocess.check_output(
                            ['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0.0'


setup(name="django-kerberos",
      version=get_version(),
      license="AGPLv3 or later",
      description="Kerberos authentication for Django",
      long_description=file('README').read(),
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="info@entrouvert.org",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      packages=find_packages('src'),
      install_requires=[
          'django>1.5',
          'pykerberos',
      ],
      package_dir={
          '': 'src',
      },
      package_data={
          'django_kerberos': [
              'templates/django_kerberos/*.html',
              'static/js/*.js',
          ],
      },
      dependency_links=[],
)
