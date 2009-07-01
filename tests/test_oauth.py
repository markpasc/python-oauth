import unittest

import oauth.oauth


class ConsumerTests(unittest.TestCase):

    def test_basic(self):
        csr = oauth.oauth.OAuthConsumer('asf', 'dasf')
        self.assertEqual(csr.key, 'asf')
        self.assertEqual(csr.secret, 'dasf')


class TokenTests(unittest.TestCase):

    def test_from_string(self):
        tok = oauth.oauth.OAuthToken.from_string('')
        self.assert_(tok.key is None)
        self.assert_(tok.secret is None)
        tok = oauth.oauth.OAuthToken.from_string('blahblahblah')
        self.assert_(tok.key is None)
        self.assert_(tok.secret is None)
        tok = oauth.oauth.OAuthToken.from_string('blah=blah')
        self.assert_(tok.key is None)
        self.assert_(tok.secret is None)

        tok = oauth.oauth.OAuthToken.from_string('oauth_token_secret=asfdasf')
        self.assertEqual(tok.secret, 'asfdasf')
        self.assert_(tok.key is None)
        tok = oauth.oauth.OAuthToken.from_string('oauth_token_secret=')
        self.assertEqual(tok.secret, '')
        self.assert_(tok.key is None)
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=asfdasf')
        self.assertEqual(tok.key, 'asfdasf')
        self.assert_(tok.secret is None)
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=')
        self.assertEqual(tok.key, '')
        self.assert_(tok.secret is None)
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=&oauth_token_secret=')
        self.assertEqual(tok.key, '')
        self.assertEqual(tok.secret, '')
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=tooken%26oauth_token_secret=seecret')
        self.assertEqual(tok.key, 'tooken&oauth_token_secret=seecret')
        self.assert_(tok.secret is None)

        tok = oauth.oauth.OAuthToken.from_string('oauth_token_secret=seecret&oauth_token=tooken')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=tooken&oauth_token_secret=seecret')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.oauth.OAuthToken.from_string('blah=blah&oauth_token=tooken&oauth_token_secret=seecret')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.oauth.OAuthToken.from_string('oauth_token=tooken&oauth_token_secret=seecret&blah=blah')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.oauth.OAuthToken.from_string('blah=blah&oauth_token=tooken&oauth_token_secret=seecret&blah=blah')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')

    def test_to_string(self):
        tok = oauth.oauth.OAuthToken(None, None)
        self.assertEqual(str(tok), '')

        tok = oauth.oauth.OAuthToken('tooken', 'seecret')
        self.assertEqual(str(tok), 'oauth_token=tooken&oauth_token_secret=seecret')


class RequestTests(unittest.TestCase):

    def test_empty(self):
        req = oauth.oauth.OAuthRequest()
        self.assertEqual(req.http_method, 'GET')
        self.assert_(req.http_url is None)
        self.assertEqual(req.parameters, {})

        self.assertEqual(req.to_postdata(), '')
        self.assertEqual(req.to_url(), '')
        self.assertEqual(req.to_header(), {})

    def test_method(self):
        req = oauth.oauth.OAuthRequest('GET')
        self.assertEqual(req.http_method, 'GET')
        self.assertEqual(req.get_normalized_http_method(), 'GET')
        req = oauth.oauth.OAuthRequest('POST')
        self.assertEqual(req.http_method, 'POST')
        self.assertEqual(req.get_normalized_http_method(), 'POST')
        req = oauth.oauth.OAuthRequest('AWESOME')
        self.assertEqual(req.http_method, 'AWESOME')
        self.assertEqual(req.get_normalized_http_method(), 'AWESOME')

        req = oauth.oauth.OAuthRequest('get')
        self.assertEqual(req.http_method, 'get')
        self.assertEqual(req.get_normalized_http_method(), 'GET')
        req = oauth.oauth.OAuthRequest('post')
        self.assertEqual(req.http_method, 'post')
        self.assertEqual(req.get_normalized_http_method(), 'POST')
        req = oauth.oauth.OAuthRequest('awesome')
        self.assertEqual(req.http_method, 'awesome')
        self.assertEqual(req.get_normalized_http_method(), 'AWESOME')

    def test_sign(self):
        req = oauth.oauth.OAuthRequest('GET', 'http://example.com/')
        self.assertEqual(req.http_method, 'GET')
        self.assertEqual(req.http_url, 'http://example.com/')

        sign = oauth.oauth.OAuthSignatureMethod_HMAC_SHA1()

        csr = oauth.oauth.OAuthConsumer('csrkey', 'csrsecret')
        token = oauth.oauth.OAuthToken('token', 'tokensecret')
        req.sign_request(sign, csr, token)

        self.assertEqual(req.to_postdata(), 'oauth_signature=mN4G%2FLGkKOPojpit%2F3LRMP1bQg8%3D&oauth_signature_method=HMAC-SHA1')
