"""
The MIT License

Copyright (c) 2007 Leah Culver

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""


import cgi
import urllib
import time
import random
import urlparse
import hmac
import binascii

from oauth import sign


VERSION = '1.0' # Hi Blaine!
HTTP_METHOD = 'GET'
SIGNATURE_METHOD = 'PLAINTEXT'


class OAuthError(RuntimeError):
    """Generic exception class."""
    def __init__(self, message='OAuth error occured.'):
        self.message = message


def escape(s):
    """Escape a URL including any /."""
    return urllib.quote(s, safe='~')


def _utf8_str(s):
    """Convert unicode to utf-8."""
    if isinstance(s, unicode):
        return s.encode("utf-8")
    else:
        return str(s)


class Consumer(object):

    """A consumer of OAuth-protected services.

    The OAuth consumer is a "third-party" service that wants to access
    protected resources from an OAuth service provider on behalf of an end
    user. It's kind of the OAuth client.

    Usually a consumer must be registered with the service provider by the
    developer of the consumer software. As part of that process, the service
    provider gives the consumer a *key* and a *secret* with which the consumer
    software can identify itself to the service. The consumer will include its
    key in each request to identify itself, but will use its secret only when
    signing requests, to prove that the request is from that particular
    registered consumer.

    Once registered, the consumer can then use its consumer credentials to ask
    the service provider for a request token, kicking off the OAuth
    authorization process.

    """

    def __init__(self, key, secret):
        if key is None:
            raise ValueError("A consumer's key must not be None")
        if secret is None:
            raise ValueError("A consumer's secret must not be None")

        self.key = key
        self.secret = secret


class Token(object):

    """An OAuth credential used to request authorization or a protected
    resource.

    Tokens in OAuth comprise a *key* and a *secret*. The key is included in
    requests to identify the token being used, but the secret is used only in
    the signature, to prove that the requester is who the server gave the
    token to.

    When first negotiating the authorization, the consumer asks for a *request
    token* that the live user authorizes with the service provider. The
    consumer then exchanges the request token for an *access token* that can
    be used to access protected resources.

    """

    def __init__(self, key, secret):
        if key is None:
            raise ValueError("A token's key must not be None")
        if secret is None:
            raise ValueError("A token's secret must not be None")

        self.key = key
        self.secret = secret

    def to_string(self):
        """Returns this token as a plain string, suitable for storage.

        The resulting string includes the token's secret, so you should never
        send or store this string where a third party can read it.

        """
        return urllib.urlencode({'oauth_token': self.key,
            'oauth_token_secret': self.secret})

    def from_string(cls, s):
        """Deserializes a token from a string like one returned by
        `to_string()`."""
        params = cgi.parse_qs(s, keep_blank_values=False)

        try:
            (key,) = params['oauth_token']
        except KeyError:
            raise ValueError("Can't make a token from string %r as it contains no key" % s)
        except ValueError:
            raise ValueError("Can't make a token from string %r as it contains more than one key" % s)

        try:
            (secret,) = params['oauth_token_secret']
        except KeyError:
            raise ValueError("Can't make a token from string %r as it contains no secret" % s)
        except ValueError:
            raise ValueError("Can't make a token from string %r as it contains more than one secret" % s)

        return cls(key, secret)
    from_string = classmethod(from_string)

    def __str__(self):
        return self.to_string()


def setter(setter):
    name = setter.__name__

    def getter(self):
        try:
            return self.__dict__[name]
        except KeyError:
            raise AttributeError(name)

    def deleter(self):
        del self.__dict__[name]

    return property(getter, setter, deleter)


class Request(dict):

    """The parameters and information for an HTTP request, suitable for
    authorizing with OAuth credentials.

    When a consumer wants to access a service's protected resources, it does
    so using a signed HTTP request identifying itself (the consumer) with its
    key, and providing an access token authorized by the end user to access
    those resources.

    """

    http_method = HTTP_METHOD
    http_url = None
    version = VERSION

    def __init__(self, method=HTTP_METHOD, url=None, parameters=None):
        if method is not None:
            self.method = method

        if url is not None:
            self.url = url

        if parameters is not None:
            self.update(parameters)

    @setter
    def url(self, value):
        parts = urlparse.urlparse(value)
        scheme, netloc, path = parts[:3]
        # Exclude default port numbers.
        if scheme == 'http' and netloc[-3:] == ':80':
            netloc = netloc[:-3]
        elif scheme == 'https' and netloc[-4:] == ':443':
            netloc = netloc[:-4]
        value = '%s://%s%s' % (scheme, netloc, path)
        self.__dict__['url'] = value

    @setter
    def method(self, value):
        self.__dict__['method'] = value.upper()

    def _get_timestamp_nonce(self):
        return self['oauth_timestamp'], self['oauth_nonce']

    def get_nonoauth_parameters(self):
        """Get any non-OAuth parameters."""
        return dict([(k, v) for k, v in self.iteritems() if not k.startswith('oauth_')])

    def to_header(self, realm=''):
        """Serialize as a header for an HTTPAuth request."""
        oauth_params = ((k, v) for k, v in self.iteritems() if k.startswith('oauth_'))
        stringy_params = ((k, escape(str(v))) for k, v in oauth_params)
        header_params = ('%s="%s"' % (k, v) for k, v in stringy_params)
        params_header = ', '.join(header_params)

        auth_header = 'OAuth realm="%s"' % realm
        if params_header:
            auth_header += params_header

        return {'Authorization': auth_header}

    def to_postdata(self):
        """Serialize as post data for a POST request."""
        return urllib.urlencode(self)

    def to_url(self):
        """Serialize as a URL for a GET request."""
        return '%s?%s' % (self.url, self.to_postdata())

    def get_normalized_parameters(self):
        """Return a string that contains the parameters that must be signed."""
        items = [(k, v) for k, v in self.items() if k != 'oauth_signature']
        return urllib.urlencode(sorted(items))

    def sign_request(self, signature_method, consumer, token):
        """Set the signature parameter to the result of build_signature."""
        self['oauth_signature_method'] = signature_method.name
        self['oauth_signature'] = signature_method.sign(self, consumer, token)

    def make_timestamp(cls):
        """Get seconds since epoch (UTC)."""
        return int(time.time())
    make_timestamp = classmethod(make_timestamp)

    def make_nonce(cls, length=8):
        """Generate pseudorandom number."""
        return ''.join([str(random.randint(0, 9)) for i in range(length)])
    make_nonce = classmethod(make_nonce)

    def from_request(cls, http_method, http_url, headers=None, parameters=None,
            query_string=None):
        """Combines multiple parameter sources."""
        if parameters is None:
            parameters = {}

        # Headers
        if headers and 'Authorization' in headers:
            auth_header = headers['Authorization']
            # Check that the authorization header is OAuth.
            if auth_header[:6] == 'OAuth ':
                auth_header = auth_header[6:]
                try:
                    # Get the parameters from the header.
                    header_params = cls._split_header(auth_header)
                    parameters.update(header_params)
                except:
                    raise OAuthError('Unable to parse OAuth parameters from '
                        'Authorization header.')

        # GET or POST query string.
        if query_string:
            query_params = cls._split_url_string(query_string)
            parameters.update(query_params)

        # URL parameters.
        param_str = urlparse.urlparse(http_url)[4] # query
        url_params = cls._split_url_string(param_str)
        parameters.update(url_params)

        if parameters:
            return cls(http_method, http_url, parameters)

        return None
    from_request = classmethod(from_request)

    def from_consumer_and_token(cls, oauth_consumer, token=None,
            http_method=HTTP_METHOD, http_url=None, parameters=None):
        if not parameters:
            parameters = {}

        defaults = {
            'oauth_consumer_key': oauth_consumer.key,
            'oauth_timestamp': cls.make_timestamp(),
            'oauth_nonce': cls.make_nonce(),
            'oauth_version': cls.version,
        }

        defaults.update(parameters)
        parameters = defaults

        if token:
            parameters['oauth_token'] = token.key

        return OAuthRequest(http_method, http_url, parameters)
    from_consumer_and_token = classmethod(from_consumer_and_token)

    def from_token_and_callback(cls, token, callback=None, http_method=HTTP_METHOD,
            http_url=None, parameters=None):
        if not parameters:
            parameters = {}

        parameters['oauth_token'] = token.key

        if callback:
            parameters['oauth_callback'] = callback

        return cls(http_method, http_url, parameters)
    from_token_and_callback = classmethod(from_token_and_callback)

    def _split_header(header):
        """Turn Authorization: header into parameters."""
        params = {}
        parts = header.split(',')
        for param in parts:
            # Ignore realm parameter.
            if param.find('realm') > -1:
                continue
            # Remove whitespace.
            param = param.strip()
            # Split key-value.
            param_parts = param.split('=', 1)
            # Remove quotes and unescape the value.
            params[param_parts[0]] = urllib.unquote(param_parts[1].strip('\"'))
        return params
    _split_header = staticmethod(_split_header)

    def _split_url_string(param_str):
        """Turn URL string into parameters."""
        parameters = cgi.parse_qs(param_str, keep_blank_values=False)
        for k, v in parameters.iteritems():
            parameters[k] = urllib.unquote(v[0])
        return parameters
    _split_url_string = staticmethod(_split_url_string)


class Client(object):

    """OAuthClient is a worker to attempt to execute a request."""

    consumer = None
    token = None

    def __init__(self, oauth_consumer, oauth_token):
        self.consumer = oauth_consumer
        self.token = oauth_token

    def get_consumer(self):
        return self.consumer

    def get_token(self):
        return self.token

    def fetch_request_token(self, oauth_request):
        """-> OAuthToken."""
        raise NotImplementedError

    def fetch_access_token(self, oauth_request):
        """-> OAuthToken."""
        raise NotImplementedError

    def access_resource(self, oauth_request):
        """-> Some protected resource."""
        raise NotImplementedError
