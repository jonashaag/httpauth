httpauth
========

a WSGI middleware that secures some/all routes using HTTP Digest Authentication.


Installation
------------
::

   pip install httpauth


Using with credentials dictionary
---------------------------------
::

   secured_wsgi_app = httpauth.DictHttpAuthMiddleware(
      {'user1': 'password1', 'user2': 'password2'},
      wsgi_app=unsecured_wsgi_app,
      #realm='Secured Content', # optional
   )


Using with a ``.htdigest`` file
-------------------------------
::

   secured_wsgi_app = httpauth.DigestFileHttpAuthMiddleware(
      open('/path/to/your/.htdigest'),
      wsgi_app=unsecured_wsgi_app,
   )

``.htdigest`` files can be created using the ``htdigest`` Apache tool.


Securing only some URLs
-----------------------
If given, the ``routes`` parameter (a list of regular expressions) specifies
the URLs to be secured.  (By default, all URLs are secured.)

::

   secured_wsgi_app = httpauth.DictHttpAuthMiddleware(
      {'user': 'password'},
      wsgi_app=unsecured_wsgi_app,
      routes=['^/admin/', '^/another/secret/page/$'],
   )
