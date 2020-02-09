from paste.debug.debugapp import SimpleApplication, SlowConsumer
from paste.fixture import TestApp


def test_fixture():
    app = TestApp(SimpleApplication())
    res = app.get('/', params={'a': ['1', '2']})
    assert (res.request.environ['QUERY_STRING'] ==
            'a=1&a=2')
    res = app.put('/')
    assert (res.request.environ['REQUEST_METHOD'] ==
            'PUT')
    res = app.delete('/')
    assert (res.request.environ['REQUEST_METHOD'] ==
            'DELETE')
    class FakeDict(object):
        def items(self):
            return [('a', '10'), ('a', '20')]
    res = app.post('/params', params=FakeDict())

    # test multiple cookies in one request
    app.cookies['one'] = 'first';
    app.cookies['two'] = 'second';
    app.cookies['three'] = '';
    res = app.get('/')
    hc = res.request.environ['HTTP_COOKIE'].split('; ');
    assert ('one=first' in hc)
    assert ('two=second' in hc)
    assert ('three=' in hc)


def test_fixture_form():
    app = TestApp(SlowConsumer())
    res = app.get('/')
    form = res.forms[0]
    assert 'file' in form.fields
    assert form.action == ''


def test_fixture_form_end():
    def response(environ, start_response):
        body = b"<html><body><form>sm\xc3\xb6rebr\xc3\xb6</form></body></html>"
        start_response("200 OK", [('Content-Type', 'text/html'),
                                  ('Content-Length', str(len(body)))])
        return [body]
    TestApp(response).get('/')
