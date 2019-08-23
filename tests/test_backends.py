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

import os

from django.contrib.auth import get_user_model, authenticate

User = get_user_model()


def test_kerberos_password(k5env, db):
    k5env.run(['kdestroy'])

    assert authenticate(username=k5env.user_princ, password='nogood') is None
    user = User.objects.create(username=k5env.user_princ, is_active=False)
    assert not user.check_password(k5env.password('user'))
    assert authenticate(username=k5env.user_princ, password=k5env.password('user')) is None
    user.is_active = True
    user.save()
    assert authenticate(username=k5env.user_princ, password=k5env.password('user')) == user
    user.refresh_from_db()
    assert user.check_password(k5env.password('user'))
    assert authenticate(username=k5env.user_princ, password=k5env.password('user')) == user
    assert not os.path.exists(k5env.ccache)
