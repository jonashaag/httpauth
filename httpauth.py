import os
import re
import time
import urllib2
import hashlib


def md5(x):
    return hashlib.md5(x).hexdigest()


def sha256(x):
    return hashlib.sha256(x).hexdigest()


class HttpAuthMiddleware(object):
    def __init__(self, wsgi_app, realm=None, routes=()):
        self.wsgi_app = wsgi_app
        self.realm = realm or ''
        self.routes = self.compile_routes(routes)

    def __call__(self, environ, start_response):
        if (self.should_require_authentication(environ) and
            not self.authenticate(environ)):
            return self.challenge(environ, start_response)
        else:
            return self.wsgi_app(environ, start_response)

    def compile_routes(self, routes):
        return map(re.compile, routes)

    def should_require_authentication(self, environ):
        return (not self.routes # require auth for all URLs
                or any(route.match(environ['PATH_INFO']) for route in self.routes))

    def authenticate(self, environ):
        try:
            hd = self.parse_dict_header(environ['HTTP_AUTHORIZATION'])
        except (KeyError, ValueError):
            return False

        return self.credentials_valid(
            hd['response'],
            environ['REQUEST_METHOD'],
            self.reconstruct_uri(environ),
            hd['nonce'],
            hd['Digest username'],
        )

    def credentials_valid(self, response, http_method, uri, nonce, user):
        return response == self.make_auth_response(nonce,
                                                   self.make_HA1(user),
                                                   self.make_HA2(http_method, uri))

    def make_auth_response(self, nonce, HA1, HA2):
        return md5(HA1 + ':' + nonce + ':' + HA2)

    def make_HA2(self, http_method, uri):
        return md5(http_method + ':' + uri)

    def reconstruct_uri(elf, environ):
        # TODO: copy from pep 3333
        uri = environ['PATH_INFO']
        if environ.get('QUERY_STRING'):
            uri += '?' + environ['QUERY_STRING']
        return uri

    def make_www_authenticate_header(self, realm=None):
        return 'Digest realm="%s", nonce="%s"' % (realm, self.generate_nonce())

    def generate_nonce(self):
        return sha256(os.urandom(1000) + str(time.time()))

    def parse_dict_header(self, value):
        return urllib2.parse_keqv_list(urllib2.parse_http_list(value))

    def challenge(self, environ, start_response):
        start_response(
            '401 Authentication Required',
            [('WWW-Authenticate', self.make_www_authenticate_header(self.realm))],
        )
        return ['<h1>401 - Authentication Required</h1>']


class DigestFileHttpAuthMiddleware(HttpAuthMiddleware):
    def __init__(self, filelike, **kwargs):
        realm, self.user_HA1_map = self.parse_htdigest_file(filelike)
        HttpAuthMiddleware.__init__(self, realm=realm, **kwargs)

    def make_HA1(self, username):
        return self.user_HA1_map.get(username, '')

    def parse_htdigest_file(self, filelike):
        realm = None
        user_HA1_map = {}

        for lineno, line in enumerate(filter(None, filelike.readlines()), 1):
            try:
                username, realm2, password_hash = line.split(':')
            except ValueError:
                raise ValueError("Line %d invalid: %r (username/password may not contain ':')" % (lineno, line))
            if realm is not None and realm != realm2:
                raise ValueError("Line %d: realm may not vary (got %r and %r)" % (lineno, realm, realm2))
            else:
                realm = realm2
                user_HA1_map[username] = password_hash

        return realm, user_HA1_map


class DictHttpAuthMiddleware(HttpAuthMiddleware):
    def __init__(self, user_password_map, **kwargs):
        self.user_password_map = user_password_map
        HttpAuthMiddleware.__init__(self, **kwargs)

    def make_HA1(self, username):
        password = self.user_password_map.get(username, '')
        return md5(username + ':' + self.realm + ':' + password)
