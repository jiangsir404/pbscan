# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php

"""Provide an html.escape method that is python method safe."""

import six

if six.PY3:
    from html import escape
else:
    # This is a copy from Python3.
    def escape(s, quote=True):
        """
        Replace special characters "&", "<" and ">" to HTML-safe sequences.  If
        the optional flag quote is true (the default), the quotation mark
        characters, both double quote (") and single quote (') characters are
        also translated.
        """
        s = s.replace("&", "&amp;") # Must be done first!
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        if quote:
            s = s.replace('"', "&quot;")
            s = s.replace('\'', "&#x27;")
        return s
