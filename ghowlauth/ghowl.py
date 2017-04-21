#!/usr/bin/env python
"""GitHub Organization WhiteList Authenticator

   This class subclasses the oauthenticator.GitHubOAuthentictor class from
   JupyterHub to add a whitelist corresponding to org membership.  We don't
   want this to be the caller's job (as would be normal), because inside
   the authenticator, we're actually authenticated with a GitHub Client ID
   and therefore we don't have to mess around granting access and then
   revoking it as we would if we succeeded and then decided the org
   membership was wrong.

   We use the environment variable GITHUB_ORGANIZATION_WHITELIST to construct
   the whitelist.

   Plus, "ghowl" sounds cool.  Like "ghoul" plus "howl".
"""

import json
import os

from oauthenticator import GitHubOAuthenticator, LocalAuthenticator, \
    GitHubLoginHandler
from tornado import gen, web
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

# *** Begin duplicated implementation ***
# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com/user'
else:
    GITHUB_API = '%s/api/v3/user' % GITHUB_HOST
# *** End duplicated implementation ***


class GHOWLLoginHandler(GitHubLoginHandler):
    """Must be able to get organization membership.

    We're going to cheat and get repo too, so that we can pass the token
    to the backend and set up the user to pull/push automagically.
    """
    scope = ["read:org", "repo"]


class GHOWLAuthenticator(GitHubOAuthenticator):
    """This is just GitHubOAuthenticator with an environment-derived
    whitelist added.  GITHUB_ORGANIZATION_WHITELIST is taken to be a
    comma-separated list of GitHub organizations.  When
    authenticating, we do the GitHub auth first.

    We then stash the access token (and some other data) in the authenticator's
    auth_context member.

    That way, when we get to check_whitelist, we replace that implementation
    with a method that looks at the value of GITHUB_ORGANIZATION_WHITELIST.
    It uses the access token to find the GitHub organizations that the user
    belongs to.  That list is intersected with the whitelist, and if the
    result isn't empty, the user is authenticated; otherwise the user is
    not permitted to log in, and the auth_context structure is cleared.
    """

    login_handler = GHOWLLoginHandler
    auth_context = {}

    # It's a Tornado coroutine
    @gen.coroutine
    def authenticate(self, handler, data=None, auth_context=None):
        """Standard GitHub OAuth, only stashing the access token.
        """
        # We are duplicating the superclass implementation because we need the
        #  access token, which is not exposed by the parent implementation.
        #  We will also grab the GitHub ID because we want it downstream.
        self.log.info("Entering GH OAuth duplicated section")
        # *** Begin duplicated implementation ***
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/

        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
            client_id=self.client_id,
            client_secret=self.client_secret,
            code=code
        )

        url = url_concat("https://%s/login/oauth/access_token" % GITHUB_HOST,
                         params)

        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers = {"Accept": "application/json",
                   "User-Agent": "JupyterHub",
                   "Authorization": "token {}".format(access_token)
                   }
        req = HTTPRequest("https://%s" % GITHUB_API,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        # *** End duplicated implementation ***
        self.log.info("Exiting GH OAuth duplicated section")
        user = resp_json["login"]
        if not user:
            self.auth_context = {}
            user = None  # Ensure it's the right kind of Not User
        else:
            uid = resp_json["id"]
            self.auth_context["username"] = user
            self.auth_context["uid"] = uid
            self.auth_context["access_token"] = "SECRET"
            self.log.info("Auth Context: %r" % self.auth_context)
            self.auth_context["access_token"] = access_token
        return user  # NOQA

    def check_whitelist(self, username):
        """Use GitHub organization whitelist."""
        ghowl = None
        ghowlenv = 'GITHUB_ORGANIZATION_WHITELIST'
        ghowlstr = os.environ.get(ghowlenv)
        if ghowlstr:
            ghowl = ghowlstr.split(',')
        stillgood = True
        if not ghowl:
            self.log.warning("No GitHub Organization whitelist; can't auth")
            self.auth_context = {}
            stillgood = False
        if stillgood and (not self.auth_context or "access_token" not
                          in self.auth_context):
            self.log.warning("No access token in authenticator: can't auth")
            self.auth_context = {}
            stillgood = False
        if stillgood:
            access_token = self.auth_context["access_token"]
            orgurl = "https://%s/orgs" % GITHUB_API
            self.log.info("About to request URL %s" % orgurl)
            headers = {"Accept": "application/json",
                       "User-Agent": "JupyterHub/%s" % username,
                       "Authorization": "token {}".format(access_token)
                       }
            orgreq = HTTPRequest(orgurl,
                                 method="GET",
                                 headers=headers
                                 )
            orghttp_client = AsyncHTTPClient()
            orgresp = yield orghttp_client.fetch(orgreq)
            orgresp_json = json.loads(orgresp.body.decode('utf8', 'replace'))
            orghttp_client.close()
            orglist = [item["login"] for item in orgresp_json]
            self.auth_context["organizations"] = orglist
            self.log.info("User %s Orgs: %s" % (username, str(orglist)))
            intersection = [org for org in orglist if org in ghowl]
            self.log.info("Intersected Orgs: %s" % str(intersection))
            if not intersection:
                # Sorry, buddy.  You're not on the list.  You're NOBODY.
                self.log.warning("User %s is not in %r" % (username, ghowl))
                self.auth_context = {}  # Forget access token and friends
                stillgood = False
        return stillgood  # NOQA


class LocalGHOWLAuthenticator(LocalAuthenticator, GHOWLAuthenticator):
    """A version that mixes in local system user creation"""
    pass
