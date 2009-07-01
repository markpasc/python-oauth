import unittest

import oauth


class ConsumerTests(unittest.TestCase):

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, None))
        self.assertRaises(ValueError, lambda: oauth.Consumer('asf', None))
        self.assertRaises(ValueError, lambda: oauth.Consumer(None, 'dasf'))

        csr = oauth.Consumer('asf', 'dasf')
        self.assertEqual(csr.key, 'asf')
        self.assertEqual(csr.secret, 'dasf')


class TokenTests(unittest.TestCase):

    def test_basic(self):
        self.assertRaises(ValueError, lambda: oauth.Token(None, None))
        self.assertRaises(ValueError, lambda: oauth.Token('asf', None))
        self.assertRaises(ValueError, lambda: oauth.Token(None, 'dasf'))

        tok = oauth.Token('asf', 'dasf')
        self.assertEqual(tok.key, 'asf')
        self.assertEqual(tok.secret, 'dasf')

    def test_from_string(self):
        self.assertRaises(ValueError, lambda: oauth.Token.from_string(''))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('blahblahblah'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('blah=blah'))

        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token_secret=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=asfdasf'))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=&oauth_token_secret='))
        self.assertRaises(ValueError, lambda: oauth.Token.from_string('oauth_token=tooken%26oauth_token_secret=seecret'))

        tok = oauth.Token.from_string('oauth_token_secret=seecret&oauth_token=tooken')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.Token.from_string('oauth_token=tooken&oauth_token_secret=seecret')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.Token.from_string('blah=blah&oauth_token=tooken&oauth_token_secret=seecret')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.Token.from_string('oauth_token=tooken&oauth_token_secret=seecret&blah=blah')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')
        tok = oauth.Token.from_string('blah=blah&oauth_token=tooken&oauth_token_secret=seecret&blah=blah')
        self.assertEqual(tok.key, 'tooken')
        self.assertEqual(tok.secret, 'seecret')

    def test_to_string(self):
        tok = oauth.Token('tooken', 'seecret')
        self.assertEqual(str(tok), 'oauth_token_secret=seecret&oauth_token=tooken')


class RequestTests(unittest.TestCase):

    def test_empty(self):
        req = oauth.Request()
        self.assertEqual(req.http_method, 'GET')
        self.assert_(req.http_url is None)
        self.assertEqual(req.parameters, {})

        self.assertEqual(req.to_postdata(), '')
        self.assertEqual(req.to_url(), '')
        self.assertEqual(req.to_header(), {})

    def test_method(self):
        req = oauth.Request('GET')
        self.assertEqual(req.http_method, 'GET')
        self.assertEqual(req.get_normalized_http_method(), 'GET')
        req = oauth.Request('POST')
        self.assertEqual(req.http_method, 'POST')
        self.assertEqual(req.get_normalized_http_method(), 'POST')
        req = oauth.Request('AWESOME')
        self.assertEqual(req.http_method, 'AWESOME')
        self.assertEqual(req.get_normalized_http_method(), 'AWESOME')

        req = oauth.Request('get')
        self.assertEqual(req.http_method, 'get')
        self.assertEqual(req.get_normalized_http_method(), 'GET')
        req = oauth.Request('post')
        self.assertEqual(req.http_method, 'post')
        self.assertEqual(req.get_normalized_http_method(), 'POST')
        req = oauth.Request('awesome')
        self.assertEqual(req.http_method, 'awesome')
        self.assertEqual(req.get_normalized_http_method(), 'AWESOME')

    def test_sign(self):
        req = oauth.Request('GET', 'http://example.com/')
        self.assertEqual(req.http_method, 'GET')
        self.assertEqual(req.http_url, 'http://example.com/')

        sign = oauth.sign.HmacSha1()

        csr = oauth.Consumer('csrkey', 'csrsecret')
        token = oauth.Token('token', 'tokensecret')
        req.sign_request(sign, csr, token)

        self.assertEqual(req.to_postdata(), 'oauth_signature=mN4G%2FLGkKOPojpit%2F3LRMP1bQg8%3D&oauth_signature_method=HMAC-SHA1')
