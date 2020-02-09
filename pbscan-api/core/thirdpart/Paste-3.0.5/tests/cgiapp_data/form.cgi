#!/usr/bin/env python

from __future__ import print_function

import cgi
import six

print('Content-type: text/plain')
print('')

if six.PY3:
    # Python 3: cgi.FieldStorage keeps some field names as unicode and some as
    # the repr() of byte strings, duh.

    class FieldStorage(cgi.FieldStorage):

        def _key_candidates(self, key):
            yield key

            try:
                # assume bytes, coerce to str
                try:
                    yield key.decode(self.encoding)
                except UnicodeDecodeError:
                    pass
            except AttributeError:
                # assume str, coerce to bytes
                try:
                    yield key.encode(self.encoding)
                except UnicodeEncodeError:
                    pass

        def __getitem__(self, key):

            superobj = super(FieldStorage, self)

            error = None

            for candidate in self._key_candidates(key):
                if isinstance(candidate, bytes):
                    # ouch
                    candidate = repr(candidate)
                try:
                    return superobj.__getitem__(candidate)
                except KeyError as e:
                    if error is None:
                        error = e

            # fall through, re-raise the first KeyError
            raise error

        def __contains__(self, key):
            superobj = super(FieldStorage, self)

            for candidate in self._key_candidates(key):
                if superobj.__contains__(candidate):
                    return True
            return False

else: # PY2

    FieldStorage = cgi.FieldStorage


form = FieldStorage()

print('Filename: %s' % form['up'].filename)
print('Name: %s' % form['name'].value)
print('Content: %s' % form['up'].file.read())
