import sys
import hmac
import urllib
import hashlib
import urlparse

from trac.config import Option
from trac.web.main import IRequestHandler
from trac.perm import IPermissionRequestor
from trac.core import Component, implements


class SSO(Component):
    """Implements Discourse Single Sign On LOGIN."""

    implements(IPermissionRequestor, IRequestHandler)

    sso_secret = Option("sso", "sso_secret", doc="Secret key used to encrypt "
                        "the payload.", default="")
    sso_redirect = Option("sso", "sso_redirect", doc="Redirect page after "
                          "succesful authentication.", default="")

    # IPermissionRequestor
    def get_permission_actions(self):
        return ["SSO_LOGIN"]

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/sso'
    
    def _encode_message(self, payload):
        """Encodes a payload as a SSO message and signature. "payload" is  
        a dictionary of key=value to send. 
        """
        msg = urllib.urlencode(payload).encode("base64")
        signed_msg = hmac.new(self.sso_secret.encode(), msg,
                              hashlib.sha256).hexdigest()
        return urllib.urlencode({"sso": msg, "sig": signed_msg})

    def _decode_message(self, payload, signature):
        """Decodes SSO message and verifies it's signature using the shared 
        secret.
        """
        signed_payload = hmac.new(self.sso_secret.encode(), payload,
                                  hashlib.sha256).hexdigest()
        if signed_payload.lower() != signature.lower():
            return {}
        return dict(urlparse.parse_qsl(payload.decode("base64")))

    def _error(self, req, message, title="Invalid Request"):
        data = {'title': title, 'type': '', 'message': message,
                'frames': [], 'traceback': None}
        req.send_error(sys.exc_info(), env=self.env, data=data)

    def process_request(self, req):
        req.perm.require("SSO_LOGIN")
        try:
            payload = req.args["sso"].encode()
            signature = req.args["sig"].encode()
        except (KeyError, UnicodeError):
            self._error(req, "Invalid Request")

        try:
            nonce = self._decode_message(payload, signature)["nonce"]
        except KeyError:
            self._error(req, "Invalid Request")
        
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
            self._error(req, "Internal Server Error", "Internal Server Error")
        
        reply = self._encode_message({"nonce": nonce,
                                      "username": username,
                                      "external_id": username,
                                      "name": name or "",
                                      "email": email or ""})
        req.redirect("%s?%s" % (self.sso_redirect, reply))
        









