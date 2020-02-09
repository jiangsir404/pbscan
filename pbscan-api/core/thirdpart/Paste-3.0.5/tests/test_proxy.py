from paste import proxy
from paste.fixture import TestApp

def test_proxy_to_website():
    # Not the most robust test...
    # need to test things like POSTing to pages, and getting from pages
    # that don't set content-length.
    app = proxy.Proxy('http://httpbin.org')
    app = TestApp(app)
    res = app.get('/')
    # httpbin is a react app now, so hard to read
    assert '<title>httpbin.org</title>' in res
