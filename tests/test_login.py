import pytest

import kerberos


@pytest.fixture
def kerberos_mock(request, mocker):
    a = {}
    d = (
        'kerberos.authGSSServerInit',
        'kerberos.authGSSServerStep',
        'kerberos.authGSSServerResponse',
        'kerberos.authGSSServerUserName',
        'kerberos.authGSSServerClean'
    )
    for name in d:
        if hasattr(request, 'param') and name in request.param:
            continue
        a[name] = mocker.patch(name)
    return a


def test_login_no_header(client, settings, kerberos_mock):
    client.get('/login/')
    for mock in kerberos_mock.values():
        assert mock.call_count == 0


@pytest.mark.parametrize('kerberos_mock', ['kerberos.authGSSServerInit'], indirect=True)
def test_login_missing_keytab(client, settings, kerberos_mock, caplog):
    resp = client.get('/login/', HTTP_AUTHORIZATION='Negotiate coin')
    for key, mock in kerberos_mock.iteritems():
        assert mock.call_count == 0
    assert 'keytab problem' in resp.content
    assert 'keytab problem' in caplog.text()


