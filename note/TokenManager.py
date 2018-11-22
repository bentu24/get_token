# -*- coding: utf-8 -*-
#       COPYRIGHT© DELL CORPORATION.
# @desc:
#
#       The module to get Authorization token via GraphAPI
#
#
# @auth:    Ben.Tu@quest.com


import requests
import webbrowser
import sys
import os
from urllib import urlencode

from six.moves import BaseHTTPServer
from six.moves import http_client
from six.moves import urllib

# The authorize URL that initiates the OAuth2 client credential flow for admin consent.
authorize_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?{0}'
# The token issuing endpoint.
token_url = 'https://login.microsoftonline.com/common/oauth2/v2.0/token'
# Default redirect url.
default_redirect_uri = 'http://localhost:8090'


class ClientRedirectServer(BaseHTTPServer.HTTPServer):
    """A server to handle OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into query_params and then stops serving.
    """
    query_params = {}


class ClientRedirectHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """A handler for OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into the servers query_params and then stops serving.
    """

    def do_GET(self):
        """Handle a GET request.

        Parses the query parameters and prints a message
        if the flow has completed. Note that we can't detect
        if an error occurred.
        """
        self.send_response(http_client.OK)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        query = self.path.split('?', 1)[-1]
        query = dict(urllib.parse.parse_qsl(query))
        self.server.query_params = query
        self.wfile.write(
            b"<html><head><title>Authentication Status</title></head>")
        self.wfile.write(
            b"<body><p>The authentication flow has completed.</p>")
        self.wfile.write(b"</body></html>")

    def log_message(self, format, *args):
        """Do not log messages to stdout while running as cmd. line program."""


class TokenManager:
    
    def __init__(self, client_id, client_secret, scopes):
        self.client_id     = client_id
        self.client_secret = client_secret
        self.scopes        = scopes
        self.token_path = os.path.dirname(os.path.realpath(__file__))
        print self.token_path
         
    def get_authorize_url(self, redirect_uri=None, state=None):
        """
            Description:
                This function creates the authorize URL that the app will direct the user to in order to sign in to
                Office 365 and give the app consent.
            Args:
                client_id: String,
                scopes: String,
                redirect_uri: String,
                state: String,
            Returns:
                String,
        """
        params = {
                'client_id'    : self.client_id,
                'scope'        : self.scopes,
                'response_type': 'code',
                'response_mode': 'query'}
        if redirect_uri is not None:
            params['redirect_uri'] = redirect_uri
        else:
            params['redirect_uri'] = default_redirect_uri
        if state is not None:
            params['state'] = state
        auth_url = authorize_url.format(urlencode(params))
        return auth_url


    def get_auth_code(self, auth_url):
        try:
            webbrowser.open(auth_url, new=1, autoraise=True)
            httpd = ClientRedirectServer(('localhost', 8090), ClientRedirectHandler)
            httpd.handle_request()
            if 'error' in httpd.query_params:
                sys.exit('Authentication request was rejected.')
            if 'code' in httpd.query_params:
                auth_code = httpd.query_params['code']
            else:
                print('Failed to find "code" in the query parameters of the redirect.')
                sys.exit('Try running with --noauth_local_webserver.')
                # auth_code = raw_input('Please enter the auth code here: ')
        except Exception, e:
            print e
        return auth_code


    def exchange_token(self, auth_code, redirect_uri=None):
        """
            Description:
                This function passes the authorization code to the token issuing endpoint, gets the token, and then returns it.
            Args:
                auth_code: String
                client_id: String,
                client_secret: String,
                scopes: String,
                redirect_uri: String,
            Returns:
                Dict,
        """
        try:
            post_data = {
                'grant_type'   : 'authorization_code',
                'code'         : auth_code,
                'client_id'    : self.client_id,
                'client_secret': self.client_secret,
                'scope'        : self.scopes}
            if redirect_uri is not None:
                post_data['redirect_uri'] = redirect_uri
            else:
                post_data['redirect_uri'] = default_redirect_uri
            r = requests.post(token_url, data=post_data)
            access_token    = r.json().get('access_token')
            refresh_token   = r.json().get('refresh_token')
            
            Token_Path = self.token_path
            Token_File = Token_Path+r'\Token.txt'
            File = open(Token_File,'w')
            File.write(refresh_token)
            File.close()
            
            return access_token
        except Exception, e:
            print e
            return 'Error retrieving token: {0} - {1}'.format(r.status_code, r.text)


    def refresh_access_token(self, redirect_uri=None):
        try:
            Token_Path    = self.token_path
            Token_File    = Token_Path+r'\Token.txt'
            File  = open(Token_File,'r+')
            refresh_token = File.read()
            File.close()
            
            header = {'content-type': 'application/x-www-form-urlencoded'}
            post_data = {
                'grant_type'   : 'refresh_token',
                'client_id'    : self.client_id,
                'client_secret': self.client_secret,
                'refresh_token': refresh_token,
                'scope'        : self.scopes}
            if redirect_uri is not None:
                post_data['redirect_uri'] = redirect_uri
            else:
                post_data['redirect_uri'] = default_redirect_uri
            r = requests.post(token_url, data=post_data, headers=header, verify=False)
            access_token    = r.json().get('access_token')
            refresh_token   = r.json().get('refresh_token')
            token_type      = r.json().get('token_type')
            # Token_Path = os.getcwd()
            # Token_File = Token_Path+r'\Token.txt'
            # File = open(Token_File,'w')
            # File.write(refresh_token)
            # File.close()
            return token_type + ' ' + access_token
        except Exception, e:
            print e
            return 'Error refreshing token: {0} - {1}'.format(r.status_code, r.text)

    # def unit_test(self, redirect_uri=None):
        # auth_url = self.get_authorize_url(redirect_uri)
        # auth_code = self.get_auth_code(auth_url)
        # print 'Authrization Code: ',auth_code
        # assecc_token = self.exchange_token(auth_code,redirect_uri)
        # print 'Assecc Token: ',assecc_token
        # return assecc_token

# if __name__ == '__main__':
    # client_id = 'd85d4ff7-3456-4006-ad46-0472f03d754a'
    # client_secret = 'CkwFv0F1DpUmOzGKPfLo0gW'
    # scopes = 'openid Offline_access https://graph.microsoft.com/files.readwrite.all'
    # tm = TokenManager(client_id,client_secret,scopes)
    # tm.unit_test()
    





