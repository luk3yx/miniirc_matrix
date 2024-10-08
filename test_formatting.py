from miniirc_matrix import _Event, _irc_to_html, _matrix_html_to_irc


def test_irc_to_html():
    assert _irc_to_html('Hello world!') == (None, set())
    assert _irc_to_html('\x02Bold') == ('<strong>Bold</strong>', set())
    assert (_irc_to_html('\x021 \x1d2\x02 3') ==
            ('<strong>1 <em>2</em></strong><em> 3</em>', set()))

    assert (_irc_to_html('@test:example.com: \x1dHello') ==
            ('<a href="https://matrix.to/#/@test:example.com">'
             '@test:example.com</a>: <em>Hello</em>', {'@test:example.com'}))


def html_to_irc(html):
    res, html_parsed_ok = _matrix_html_to_irc(_Event({
        'format': 'org.matrix.custom.html',
        'formatted_body': html,
    }))
    assert html_parsed_ok
    return res


def test_html_to_irc():
    assert html_to_irc('Hello <b>world</b>!') == 'Hello \x02world\x02!'
    assert html_to_irc('Hello\nworld!') == 'Hello\nworld!'
    assert html_to_irc('Hello<br>world!') == 'Hello\nworld!'
    assert html_to_irc('Hello<br/>world!') == 'Hello\nworld!'
