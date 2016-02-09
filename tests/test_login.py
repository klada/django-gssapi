import pytest

import kerberos


def test_login_no_header(client, settings):
    print client.get('/login/')

def test_login_negotiate_wrong(client, settings):
    print client.get('/login/', HTTP_AUTHORIZATION='Negotiate coin')
