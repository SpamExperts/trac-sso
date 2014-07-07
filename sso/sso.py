import sys
import hmac
import urllib
import hashlib
import urlparse
import collections

from trac.web.main import IRequestHandler
from trac.perm import IPermissionRequestor
from trac.core import Component, implements


class SSO(Component):
    """Implements Discourse Single Sign On LOGIN."""

    implements(IPermissionRequestor, IRequestHandler)

    def __init__(self, *args, **kwargs):
        Component.__init__(self, *args, **kwargs)
        self.__parse_config()

    def __parse_config(self):
        self.__endpoints = collections.defaultdict(dict)
        for key, value in self.config.options("sso"):
            try:
                endpoint, option = key.split(".", 1)
            except ValueError:
                # The default endpoint is /sso
                endpoint, option = "sso", key
            self.__endpoints[endpoint][option] = value


    # IPermissionRequestor
    def get_permission_actions(self):
        return ["SSO_LOGIN"]

    # IRequestHandler methods
    def match_request(self, req):
        if req.path_info.lstrip("/") in self.__endpoints: 
            endpoint = self.__endpoints[req.path_info.lstrip("/")]
            self.sso_secret = endpoint["sso_secret"]
            self.sso_redirect = endpoint["sso_redirect"]
            return True
        return False
    
    def __encode_message(self, payload):
        """Encodes a payload as a SSO message and signature. "payload" is  
        a dictionary of key=value to send. 
        """
        msg = urllib.urlencode(payload).encode("base64")
        signed_msg = hmac.new(self.sso_secret.encode(), msg,
                              hashlib.sha256).hexdigest()
        return urllib.urlencode({"sso": msg, "sig": signed_msg})

    def __decode_message(self, payload, signature):
        """Decodes SSO message and verifies its signature using the shared 
        secret.
        """
        signed_payload = hmac.new(self.sso_secret.encode(), payload,
                                  hashlib.sha256).hexdigest()
        if signed_payload.lower() != signature.lower():
            return {}
        return dict(urlparse.parse_qsl(payload.decode("base64")))

    def __error(self, req, message, title="Invalid Request"):
        data = {'title': title, 'type': '', 'message': message,
                'frames': [], 'traceback': None}
        req.send_error(sys.exc_info(), env=self.env, data=data)

    def process_request(self, req):
        req.perm.require("SSO_LOGIN")
        try:
            payload = req.args["sso"].encode()
            signature = req.args["sig"].encode()
        except (KeyError, UnicodeError):
            self.__error(req, "Invalid Request")

        try:
            nonce = self.__decode_message(payload, signature)["nonce"]
        except KeyError:
            self.__error(req, "Invalid Request")
        
        row = self.env.db_query("""
            SELECT DISTINCT s.sid, n.value, e.value
            FROM session AS s
             LEFT JOIN session_attribute AS n ON (n.sid=s.sid
              and n.authenticated=1 AND n.name = 'name')
             LEFT JOIN session_attribute AS e ON (e.sid=s.sid
              AND e.authenticated=1 AND e.name = 'email')
            WHERE s.authenticated=1 AND s.sid=%s LIMIT 1
            """, (req.perm.username,))

        try:
            username, name, email = row[0]
        except (IndexError, ValueError):
            self.__error(req, "Internal Server Error", "Internal Server Error")
        
        reply = self.__encode_message({"nonce": nonce,
                                       "username": username,
                                       "external_id": username,
                                       "name": name or "",
                                       "email": email or ""})
        req.redirect("%s?%s" % (self.sso_redirect, reply))
        









