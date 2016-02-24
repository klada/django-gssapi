#! /usr/bin/env python

import subprocess
import os

from setuptools import setup, find_packages
from setuptools.command.sdist import sdist


class eo_sdist(sdist):
    def run(self):
        print "creating VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        sdist.run(self)
        print "removing VERSION file"
        if os.path.exists('VERSION'):
            os.remove('VERSION')


def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git', 'describe', '--dirty', '--match=v*'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            result = result.split()[0][1:]
        else:
            result = '0.0.0-%s' % len(subprocess.check_output(
                ['git', 'rev-list', 'HEAD']).splitlines())
        return result.replace('-', '.').replace('.g', '+g')
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
      cmdclass={'sdist': eo_sdist})
