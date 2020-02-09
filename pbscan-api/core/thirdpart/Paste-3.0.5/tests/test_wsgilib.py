import pytest

from paste.wsgilib import add_close


def app_iterable_func_bytes():
    yield b'a'
    yield b'b'
    yield b'c'


def app_iterable_func_unicode():
    yield b'a'.decode('ascii')
    yield b'b'.decode('ascii')
    yield b'c'.decode('ascii')


def close_func():
    global close_func_called
    close_func_called = True


@pytest.mark.parametrize("app_iterable_func,expected", [
    (app_iterable_func_bytes, [b'a', b'b', b'c']),
    (app_iterable_func_unicode, ['a', 'b', 'c']),
])
def test_add_close(app_iterable_func, expected):
    global close_func_called

    close_func_called = False
    lst = []
    app_iterable = app_iterable_func()

    obj = add_close(app_iterable, close_func)
    for x in obj:
        lst.append(x)
    obj.close()

    assert lst == expected
    assert close_func_called
    assert obj._closed
