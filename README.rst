httpauth
========

a WSGI middleware that secures some/all routes using HTTP Digest Authentication.

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

   secured_wsgi_app = htdigest.DigestFileHttpAuthMiddleware(
      open('/path/to/your/.htdigest'),
      wsgi_app=unsecured_wsgi_app,
   )

``.htdigest`` files can be created using the ``htdigest`` Apache tool.
