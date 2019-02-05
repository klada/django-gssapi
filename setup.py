#! /usr/bin/env python

import subprocess
import os

from setuptools import setup, find_packages
from setuptools.command.sdist import sdist


class eo_sdist(sdist):
    def run(self):
        print("creating VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')
        version = get_version()
        version_file = open('VERSION', 'w')
        version_file.write(version)
        version_file.close()
        sdist.run(self)
        print("removing VERSION file")
        if os.path.exists('VERSION'):
            os.remove('VERSION')


def get_version():
    '''Use the VERSION, if absent generates a version with git describe, if not
       tag exists, take 0.0- and add the length of the commit log.
    '''
    if os.path.exists('VERSION'):
        with open('VERSION', 'r') as v:
            return v.read()
    if os.path.exists('.git'):
        p = subprocess.Popen(['git', 'describe', '--dirty=.dirty','--match=v*'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        result = p.communicate()[0]
        if p.returncode == 0:
            result = result.decode('ascii').strip()[1:]  # strip spaces/newlines and initial v
            if '-' in result:  # not a tagged version
                real_number, commit_count, commit_hash = result.split('-', 2)
                version = '%s.post%s+%s' % (real_number, commit_count, commit_hash)
            else:
                version = result
            return version
        else:
            return '0.0.post%s' % len(
                subprocess.check_output(
                    ['git', 'rev-list', 'HEAD']).splitlines())
    return '0.0'

setup(name="django-kerberos",
      version=get_version(),
      license="AGPLv3 or later",
      description="Kerberos authentication for Django",
      long_description=open('README').read(),
      url="http://dev.entrouvert.org/projects/authentic/",
      author="Entr'ouvert",
      author_email="info@entrouvert.org",
      maintainer="Benjamin Dauvergne",
      maintainer_email="bdauvergne@entrouvert.com",
      packages=find_packages('src'),
      zip_safe=False,
      include_package_data=True,
      install_requires=[
          'six',
          'django>1.8',
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
