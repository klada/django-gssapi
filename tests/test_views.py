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

import logging

import gssapi

from django.contrib.auth import get_user_model

User = get_user_model()


def test_login(k5env, client, caplog, db, settings):
    caplog.set_level(logging.DEBUG)

    response = client.get('/login/')
    assert response.status_code == 401

    response = client.get('/login/', HTTP_AUTHORIZATION='Negotiate xxx')
    assert response.status_code == 401
    assert '_auth_user_id' not in client.session

    response = client.get('/login/', HTTP_AUTHORIZATION=k5env.spnego())
    assert response.status_code == 401
    assert '_auth_user_id' not in client.session

    # create an user...
    user = User.objects.create(username=k5env.user_princ, is_active=False)

    # still no good, user is inactive
    response = client.get('/login/', HTTP_AUTHORIZATION=k5env.spnego())
    assert response.status_code == 401
    assert '_auth_user_id' not in client.session

    user.is_active = True
    user.save()
    # and retry.
    response = client.get('/login/', HTTP_AUTHORIZATION=k5env.spnego())

    assert response.status_code == 302
    assert int(client.session['_auth_user_id']) == user.id

    # break service name resolution
    settings.GSSAPI_NAME = gssapi.Name('HTTP@localhost', gssapi.NameType.hostbased_service)
    response = client.get('/login/', HTTP_AUTHORIZATION=k5env.spnego())
    assert response.status_code == 401
