import unittest

import oauth.oauth


class ConsumerTests(unittest.TestCase):

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthConsumer(None, None))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthConsumer('asf', None))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthConsumer(None, 'dasf'))

        csr = oauth.oauth.OAuthConsumer('asf', 'dasf')
        self.assertEqual(csr.key, 'asf')
        self.assertEqual(csr.secret, 'dasf')


class TokenTests(unittest.TestCase):

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken(None, None))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken('asf', None))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken(None, 'dasf'))

        tok = oauth.oauth.OAuthToken('asf', 'dasf')
        self.assertEqual(tok.key, 'asf')
        self.assertEqual(tok.secret, 'dasf')

    def test_from_string(self):
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string(''))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('blahblahblah'))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('blah=blah'))

        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token_secret=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token='))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token=&oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.oauth.OAuthToken.from_string('oauth_token=tooken%26oauth_token_secret=seecret'))

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
        tok = oauth.oauth.OAuthToken('tooken', 'seecret')
        self.assertEqual(str(tok), 'oauth_token_secret=seecret&oauth_token=tooken')


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
