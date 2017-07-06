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
import string

from oauthenticator import GitHubOAuthenticator, GitHubLoginHandler
from tornado import gen
from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient
from .common import next_page_from_links

# *** Begin duplicated implementation ***
# Support github.com and github enterprise installations
GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
if GITHUB_HOST == 'github.com':
    GITHUB_API = 'api.github.com'
else:
    GITHUB_API = '%s/api/v3' % GITHUB_HOST


def _api_headers(access_token):
    return {"Accept": "application/vnd.github.v3+json",
            "User-Agent": "JupyterHub",
            "Authorization": "token {}".format(access_token)
            }
# *** End duplicated implementation ***


class GHOWLLoginHandler(GitHubLoginHandler):
    """Must be able to get organization membership, hence read:org.

    We're going to cheat and get public_repo too, so that we can pass
    the token to the backend and set up the user to pull/push
    automagically.  (We are implicitly presuming that the repositories we
    care about for the LSST use case will be public, or at least that if
    someone cares a lot about using this with a private repo, entering
    credentials by hand doesn't seem like a big deal.)

    User:email lets us get an email address for the user, also used
    for .gitconfig creation on the backend.  If the primary email
    address is private, it's still going to come back empty, so it's
    not really all that useful.

    """
    scope = ["read:org", "public_repo", "user:email"]


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
    github_organization_whitelist = None

    # It's a Tornado coroutine
    @gen.coroutine
    def authenticate(self, handler, data=None, auth_context=None):
        """Start by making sure the org whitelist even exists.  If not,
        just give up immediately.

        After that, it's standard GitHub OAuth, except that we stash a bunch
        of data to pass to user creation.
        """
        if not self.github_organization_whitelist:
            ghowls = None
            ghowlenv = 'GITHUB_ORGANIZATION_WHITELIST'
            autherr = "No GitHub Organization Whitelist: cannot auth"
            ghowlstr = os.environ.get(ghowlenv)
            if ghowlstr:
                ghowls = ghowlstr.split(',')
            if not ghowls:
                self.log.warning(autherr)
                return None  # NoQA
            self.github_organization_whitelist = ghowls
        # We are duplicating the superclass implementation because we need the
        #  access token, which is not exposed by the parent implementation.
        #  We will also grab the GitHub ID because we want it downstream.
        self.log.info("Entering GH OAuth duplicated section")
        # *** Begin duplicated implementation ***
        code = handler.get_argument("code")
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
        url = "https://%s/user" % GITHUB_API
        headers = _api_headers(access_token)
        req = HTTPRequest(url,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        self.log.info("GH User Response: %s", json.dumps(
            resp_json, sort_keys=True, indent=4))

        username = resp_json["login"]

        # Check if user is a member of any whitelisted organizations.
        # This check is performed here, as it requires `access_token`.
        # *** Modified implementation
        if self.github_organization_whitelist and username:
            for org in self.github_organization_whitelist:
                user_in_org = yield self._check_organization_whitelist(org, username, access_token)
                if not user_in_org:
                    return None
        else:  # no organization whitelisting
            return username

        # *** End duplicated implementation ***
        self.log.info("Exiting GH OAuth duplicated section")
        if not username:
            return None  # NoQA
        safe_chars = set(string.ascii_lowercase + string.digits)
        safe_username = ''.join(
            [s if s in safe_chars else '-' for s in username.lower()])
        self.auth_context[safe_username] = {}
        acu = self.auth_context[safe_username]
        acu["username"] = username
        acu["canonicalname"] = safe_username
        acu["uid"] = resp_json["id"]
        acu["name"] = resp_json["name"]
        if "email" in resp_json and resp_json["email"]:
            acu["email"] = resp_json["email"]
        acu["access_token"] = "[secret]"
        self.log.info("Auth context [%s]: %s" % (username,
                                                 json.dumps(acu,
                                                            indent=4,
                                                            sort_keys=True)))
        # This seems a little fishy.
        acu["access_token"] = access_token
        return username  # NoQA

    @gen.coroutine
    def _check_organization_whitelist(self, org, username, access_token):
        http_client = AsyncHTTPClient()
        headers = _api_headers(access_token)
        # Get all the members for organization 'org'
        next_page = "https://%s/orgs/%s/members" % (GITHUB_API, org)
        while next_page:
            req = HTTPRequest(next_page, method="GET", headers=headers)
            resp = yield http_client.fetch(req)
            resp_json = json.loads(resp.body.decode('utf8', 'replace'))
            next_page = next_page_from_links(resp)
            org_members = set(entry["login"] for entry in resp_json)
            # check if any of the organizations seen thus far are in whitelist
            if username in org_members:
                return True  # NoQA
        return False
