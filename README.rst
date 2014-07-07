trac-sso
========

The TracSSO plugin enables SSO support for trac.

Installing:

 - From a checkout of the project run:
 
   $ python setup.py bdist_egg

 - Copy the generated egg to the plugin directory of your trac project:

   $ cp dist/TracSSO-*.egg {trac-location}/plugins/.

 - Restart trac

The plug-in adds support for `Discourse SSO <https://meta.discourse.org/t/official-single-sign-on-for-discourse/13045>`_ 
to Trac. To configure the add to your Trac configuration file the shared secret and redirect url. For example::

    [sso]
    sso_secret = thisisatestsecret
    sso_redirect = https://my.discourse.example.com/session/sso_login
    
And grant the ``SSO_LOGIN`` permission to any users/groups of users you want to. 


