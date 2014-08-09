#! /usr/bin/env python

''' Setup script for django-kerberos
'''

from setuptools import setup, find_packages

def get_version():
    import glob
    import re
    import os

    version = None
    for d in glob.glob('src/*'):
        if not os.path.isdir(d):
            continue
        module_file = os.path.join(d, '__init__.py')
        if not os.path.exists(module_file):
            continue
        for v in re.findall("""__version__ *= *['"](.*)['"]""",
                open(module_file).read()):
            assert version is None
            version = v
        if version:
            break
    assert version is not None
    if os.path.exists('.git'):
        import subprocess
        p = subprocess.Popen(['git','describe','--dirty','--match=v*'],
                stdout=subprocess.PIPE)
        result = p.communicate()[0]
        assert p.returncode == 0, 'git returned non-zero'
        new_version = result.split()[0][1:]
        assert new_version.split('-')[0] == version, '__version__ must match the last git annotated tag'
        version = new_version.replace('-', '.')
    return version


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
          'kerberos',
      ],
      package_dir={
          '': 'src',
      },
      package_data={
          'django_kerberos': [
              'templates/django_kerberos/*.html',
          ],
      },
      dependency_links=[],
)
