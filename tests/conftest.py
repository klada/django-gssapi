# django-gssapi - SPNEGO/Kerberos authentication for Django applications
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

from __future__ import unicode_literals

import base64
import os
import pytest

import gssapi

import k5test
import k5test._utils

from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.fixture
def k5env():
    k5realm = k5test.K5Realm()
    old_environ = os.environ.copy()
    try:

        os.environ.update(k5realm.env)
        k5realm.http_princ = 'HTTP/testserver@%s' % k5realm.realm
        k5realm.addprinc(k5realm.http_princ)
        k5realm.extract_keytab(k5realm.http_princ, k5realm.keytab)

        def spnego():
            service_name = gssapi.Name(k5realm.http_princ)
            service_name.canonicalize(gssapi.MechType.kerberos)

            # first attempt
            ctx = gssapi.SecurityContext(usage='initiate', name=service_name)
            return 'Negotiate %s' % base64.b64encode(ctx.step()).decode('ascii')
        k5realm.spnego = spnego
        yield k5realm
    finally:
        os.environ.clear()
        os.environ.update(old_environ)
        k5realm.stop()


@pytest.fixture
def user_princ(k5env):
    return User.objects.create(username=k5env.user_princ)

