"""
Copyright (c) 2012 Jonas Haag <jonas@lophus.org>. License: ISC

This implements Digest Auth as specified in RFC 2069, i.e. without the
`qop` quality-of-protection, `cnonce` nonce count, ... options.

References to the algorithm (HA1, HA2, nonce, ...) are taken from Wikipedia:

    http://en.wikipedia.org/wiki/Digest_access_authentication

"""
import os
import re
import time
import hashlib
try: # Python 3
    from urllib.request import parse_http_list, parse_keqv_list
except ImportError: # Python 2
    from urllib2 import parse_http_list, parse_keqv_list


def md5(x):
    return hashlib.md5(x).hexdigest()

def md5_str(x):
    return md5(x.encode('utf8'))

def sha256(x):
    return hashlib.sha256(x).hexdigest()


def reconstruct_uri(environ):
    """
    Reconstruct the relative part of the request URI. I.e. if the requested URL
    is https://foo.bar/spam?eggs, ``reconstruct_uri`` returns ``'/spam?eggs'``.
    """
    uri = environ.get('SCRIPT_NAME', '') + environ['PATH_INFO']
    if environ.get('QUERY_STRING'):
        uri += '?' + environ['QUERY_STRING']
    return uri


def make_www_authenticate_header(realm=None):
    return 'Digest realm="%s", nonce="%s"' % (realm, generate_nonce())

def generate_nonce():
    return sha256(os.urandom(1000) + str(time.time()).encode())


def make_auth_response(nonce, HA1, HA2):
    """ response := md5(HA1 : nonce : HA2) """
    return md5_str(HA1 + ':' + nonce + ':' + HA2)

def make_HA2(http_method, uri):
    """ HA2 := http_method : uri (as reconstructed by ``reconstruct_uri``) """
    return md5_str(http_method + ':' + uri)


def parse_dict_header(value):
    """
    Parses a HTTP dict header value -- i.e. ``"foo=bar, spam=eggs"`` is parsed
    into ``{'foo': 'bar', 'spam': 'eggs'}``.
    """
    return parse_keqv_list(parse_http_list(value))


class BaseHttpAuthMiddleware(object):
    """
    Abstract HTTP Digest Auth middleware. Contains all the functionality
    except for credential validation  -- this happens using the ``make_HA1``
    method which needs to be overriden by subclasses.

    `wsgi_app`
       The WSGI app to be secured.
    `realm`
       The HTTP Auth realm to be displayed in the browser.
    `routes`
       (optional) A list of regular expressions that specify which URLs should
       be secured. If not given, all routes are secured by default.
    """
    def __init__(self, wsgi_app, realm=None, routes=()):
        self.wsgi_app = wsgi_app
        self.realm = realm or ''
        self.routes = self.compile_routes(routes)

    def __call__(self, environ, start_response):
        environ['httpauth.uri'] = reconstruct_uri(environ)
        if (self.should_require_authentication(environ['httpauth.uri']) and
            not self.authenticate(environ)):
            # URL is secured and user hasn't sent authentication/wrong credentials.
            return self.challenge(environ, start_response)
        else:
            # Wave-through to real WSGI app.
            return self.wsgi_app(environ, start_response)

    def compile_routes(self, routes):
        return [re.compile(route) for route in routes]

    def should_require_authentication(self, url):
        """ Returns True if we should require authentication for the URL given """
        return (not self.routes # require auth for all URLs
                or any(route.match(url) for route in self.routes))

    def authenticate(self, environ):
        """
        Returns True if the credentials passed in the Authorization header are
        valid, False otherwise.
        """
        try:
            hd = parse_dict_header(environ['HTTP_AUTHORIZATION'])
        except (KeyError, ValueError):
            return False

        return self.credentials_valid(
            hd['response'],
            environ['REQUEST_METHOD'],
            environ['httpauth.uri'],
            hd['nonce'],
            hd['Digest username'],
        )

    def credentials_valid(self, response, http_method, uri, nonce, user):
        try:
            HA1 = self.make_HA1(user)
        except KeyError:
            # Invalid user
            return False
        return response == make_auth_response(nonce, HA1, make_HA2(http_method, uri))

    def challenge(self, environ, start_response):
        start_response(
            '401 Authentication Required',
            [('WWW-Authenticate', make_www_authenticate_header(self.realm))],
        )
        return ['<h1>401 - Authentication Required</h1>']


class DigestFileHttpAuthMiddleware(BaseHttpAuthMiddleware):
    """
    Reads credentials from an Apache-style .htdigest file.

    `filelike`
       Any file-like object that has a ``.read()`` method.
       Note: Don't pass filenames, only open files/file-likes.
    """
    def __init__(self, filelike, **kwargs):
        realm, self.user_HA1_map = self.parse_htdigest_file(filelike)
        BaseHttpAuthMiddleware.__init__(self, realm=realm, **kwargs)

    def make_HA1(self, username):
        return self.user_HA1_map[username]

    def parse_htdigest_file(self, filelike):
        """
        .htdigest files consist of lines in the following format::

            username:realm:passwordhash

        where both `username` and `realm` are plain-text without any colons
        and `passwordhash` is the result of ``md5(username : realm : password)``
        and thus `passwordhash` == HA1.
        """
        realm = None
        user_HA1_map = {}

        for lineno, line in enumerate(filter(None, filelike.read().splitlines()), 1):
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


class DictHttpAuthMiddleware(BaseHttpAuthMiddleware):
    """
    Reads credentials from ``user_password_map`` which is a
    `username -> plaintext password` map.
    """
    def __init__(self, user_password_map, **kwargs):
        self.user_password_map = user_password_map
        BaseHttpAuthMiddleware.__init__(self, **kwargs)

    def make_HA1(self, username):
        password = self.user_password_map[username]
        return md5_str(username + ':' + self.realm + ':' + password)


class AlwaysFailingAuthMiddleware(BaseHttpAuthMiddleware):
    """ This thing just keeps asking for credentials all the time """
    def authenticate(self, environ):
        return False
