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

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from django_gssapi.drf import GSSAPIAuthentication, add_gssapi_mutual_auth


class RestView(APIView):
    authentication_classes = [GSSAPIAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        response = Response({
            'user': str(request.user),
            'auth': str(request.auth),
        })
        add_gssapi_mutual_auth(request, response)
        return response

view = RestView.as_view()


def test_gssapi_authentication_no_auth(k5env, db, rf):
    request = rf.get('/')
    response = view(request)
    assert response.status_code == 401
    assert response['WWW-Authenticate'] == 'Negotiate'


def test_gssapi_authentication_no_user(k5env, db, rf):
    request = rf.get('/', HTTP_AUTHORIZATION=k5env.spnego())
    response = view(request)
    assert response.status_code == 401
    assert response['WWW-Authenticate'] == 'Negotiate'


def test_gssapi_authentication_passing(k5env, db, rf, user_princ):
    request = rf.get('/', HTTP_AUTHORIZATION=k5env.spnego())
    response = view(request)
    assert response.status_code == 200
    assert response.data['user'] == k5env.user_princ
    assert response.data['auth'] == k5env.user_princ
    assert response['WWW-Authenticate'].startswith('Negotiate ')
