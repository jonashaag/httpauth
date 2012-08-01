import re
import urllib2

from StringIO import StringIO
from httpauth import DictHttpAuthMiddleware, DigestFileHttpAuthMiddleware, md5

from nose.tools import raises


def parse_dict_header(value):
    return urllib2.parse_keqv_list(urllib2.parse_http_list(value))


def make_auth_response(http_method, uri, realm, nonce, user, password):
    HA1 = md5(':'.join([user, realm, password]))
    HA2 = md5(':'.join([http_method, uri]))
    return md5(':'.join([HA1, nonce, HA2]))


class Response:
    """
    Attributes:
    - status_code
    - headers
    - body
    """
    def get_nonce(self):
        return self.headers['WWW-Authenticate'][-64-1:-1]


def wsgi_app(environ, start_response):
    start_response('200 OK', [])
    return [environ['PATH_INFO']]


def make_dict_app(**kwargs):
    return DictHttpAuthMiddleware(
        {'user': 'password'},
        wsgi_app=wsgi_app,
        **kwargs
    )


def make_digest_app(**kwargs):
    return DigestFileHttpAuthMiddleware(
        StringIO('user:myrealm:04cb1ff8d2b798abd28d64db0fffe896\n'),
        wsgi_app=wsgi_app,
        **kwargs
    )

def request(app, url, nonce=None, username=None, password=None, method='GET'):
    response = Response()

    def start_response(status_code, headers):
        response.status_code = int(status_code.split(' ')[0])
        response.headers = dict(headers)

    env = {
        'REQUEST_METHOD': method,
        'PATH_INFO': url.split('?')[0] if '?' in url else url,
        'QUERY_STRING': url.split('?')[1] if '?' in url else '',
    }

    if nonce:
        env['HTTP_AUTHORIZATION'] = 'Digest username="%s", nonce="%s", response="%s"' \
            % (username, nonce, make_auth_response(method, url, app.realm,
                                                   nonce, username, password))

    iterable = app(env, start_response)
    response.body = ''.join(iterable)
    return response


def test_no_routes():
    app1 = make_dict_app(realm='myrealm')
    app2 = make_digest_app()

    for app in [app1, app2]:
        # Without username/password
        response = request(app, '/foo/?a=b')
        assert response.status_code == 401
        assert re.match('Digest realm="myrealm", nonce="[a-z0-9]{64}"',
                        response.headers['WWW-Authenticate'])
        assert 'Authentication Required' in response.body
        assert '/foo/' not in response.body

        # Wrong username/password
        for username, password in [
            ('user', 'wrong password'),
            ('wrong user', 'password'),
            ('', 'password'),
            ('user', ''),
        ]:
            nonce = response.get_nonce()
            assert len(nonce) == 64
            response = request(app, '/foo/', nonce, username, password)
            assert response.status_code == 401

        # Correct credentials
        response = request(app, '/foo/?a=b', nonce, 'user', 'password')
        assert response.status_code == 200
        assert 'foo' in response.body


def test_with_routes():
    app = make_dict_app(routes=['^/a'])
    assert request(app, '/a').status_code == 401
    assert request(app, '/b').status_code == 200


def test_without_realm():
    app = DictHttpAuthMiddleware({'user': 'password'}, wsgi_app=wsgi_app)
    response = request(app, '/')
    assert response.status_code == 401
    assert 'Digest realm=""' in response.headers['WWW-Authenticate']


@raises(ValueError)
def test_invalid_digestfile_1():
    DigestFileHttpAuthMiddleware(StringIO('u::realm:hash'),
                                 wsgi_app=wsgi_app)


@raises(ValueError)
def test_invalid_digestfile_2():
    DigestFileHttpAuthMiddleware(StringIO('u:realm:hash\nu2:realm2:hash2'),
                                 wsgi_app=wsgi_app)


def test_ticket_1():
    """ Reject non-existent users if empty password is sent """
    app1 = make_dict_app()
    app2 = make_digest_app()

    for app in [app1, app2]:
        response = request(app, '/')
        nonce = response.get_nonce()
        assert request(app, '/', nonce, 'not-a-user', '').status_code == 401
