#
# miniirc_matrix
#
# Copyright © 2021 by luk3yx
#

from __future__ import annotations
from collections.abc import Callable
from typing import Any, Optional, TypeVar, overload
from urllib.parse import quote as _url_quote
import functools, html.parser, itertools, json, math, re, threading, time, uuid
import miniirc, requests, traceback  # type: ignore


ver = (0, 0, 1)
__version__ = '.'.join(map(str, ver))


def _room_processor(*event_names: str):
    def _make_wrapper(f: Callable[[Matrix, str, dict[str, Any]], None]
                      ) -> Callable[[Matrix, dict[str, Any]], None]:
        @functools.wraps(f)
        def wrapper(self: Matrix, sync_msg: dict[str, Any]) -> None:
            for event_name in event_names:
                if event_name in sync_msg:
                    for room_id, room in sync_msg[event_name].items():
                        f(self, room_id, room)

        return wrapper

    return _make_wrapper


# Register events
_events: dict[str, Callable[[Matrix, str, _Event], None]] = {}


def _register_event(event_name: str):
    def _register(f: Callable[[Matrix, str, _Event], None]
                  ) -> Callable[[Matrix, str, _Event], None]:
        assert event_name not in _events
        _events[event_name] = f
        return f

    return _register


_formatting_re = re.compile(
    r'\x02|\x1d|\x1f|\x1e|\x11|\x16|\x0f'
    r'|\x03([0-9]{1,2})?(?:,([0-9]{1,2}))?'
    r'|\x04([0-9a-fA-F]{6})?(?:,([0-9a-fA-F]{6}))?'
)
_html_tags = {'\x02': 'strong', '\x1d': 'em', '\x1f': 'u', '\x1e': 'del',
              '\x11': 'code'}


class _TagManager:
    __slots__ = ('text', 'formatting', 'open_tags', 'tags', 'fg', 'bg',
                 'reverse_colours')

    def __init__(self) -> None:
        self.text: list[str] = []
        self.tags: dict[str, str] = {}
        self.open_tags: dict[str, str] = {}
        self.fg: Optional[str] = None
        self.bg: Optional[str] = None
        self.reverse_colours: bool = False

    def write_tags(self) -> None:
        if self.tags != self.open_tags:
            open_tags = tuple(self.open_tags.items())
            tags = tuple(self.tags.items())
            i = 0
            for a, b in zip(open_tags, tags):
                if a != b:
                    break
                i += 1

            self.text.extend(f'</{t.split(" ", 1)[0]}>'
                             for t, _ in reversed(open_tags[i:]))
            self.text.extend(f'<{t}{params}>' for t, params in tags[i:])
            self.open_tags = self.tags.copy()

    def write(self, s: str) -> None:
        if s:
            self.write_tags()
            self.text.append(s)

    def open(self, tag: str, **kwargs: Optional[str]) -> None:
        self.tags[tag] = ''.join(
            f' data-mx-{param.replace("_", "-")}="{value}"'
            for param, value in kwargs.items() if value is not None
        )

        # Fix ordering
        if self.tags == self.open_tags:
            self.tags = self.open_tags.copy()

    def set_colours(self, fg: Optional[str] = None,
                    bg: Optional[str] = None) -> None:
        if fg is not None:
            self.fg = fg
        if bg is not None:
            self.bg = bg

        if not self.fg and not self.bg:
            if 'span' in self.tags:
                self.close('span')
        elif self.fg == self.bg:
            self.open('span', spoiler='')
        elif self.reverse_colours:
            # This won't work for the "default" colour
            self.open('span', color=self.bg, bg_color=self.fg)
        else:
            self.open('span', color=self.fg, bg_color=self.bg)

    def close(self, tag: str) -> None:
        del self.tags[tag]

    def toggle(self, tag: str) -> None:
        if tag in self.tags:
            self.close(tag)
        else:
            self.open(tag)


_colours = (
    0xffffff,  # White
    0x000000,  # Black
    0x00007f,  # Blue
    0x009300,  # Green
    0xff0000,  # Red
    0xa52a2a,  # Brown
    0xff00ff,  # Magenta
    0xffa500,  # Orange
    0xffff00,  # Yellow
    0x90ee90,  # Light green
    0x00ffff,  # Cyan
    0xe0ffff,  # Light cyan
    0xadd8e6,  # Light blue
    0xffc0cb,  # Pink
    0x808080,  # Grey
    0xd3d3d3,  # Light grey

    # Colours 16-98
    0x470000, 0x472100, 0x474700, 0x324700, 0x004700, 0x00472c, 0x004747,
    0x002747, 0x000047, 0x2e0047, 0x470047, 0x47002a, 0x740000, 0x743a00,
    0x747400, 0x517400, 0x007400, 0x007449, 0x007474, 0x004074, 0x000074,
    0x4b0074, 0x740074, 0x740045, 0xb50000, 0xb56300, 0xb5b500, 0x7db500,
    0x00b500, 0x00b571, 0x00b5b5, 0x0063b5, 0x0000b5, 0x7500b5, 0xb500b5,
    0xb5006b, 0xff0000, 0xff8c00, 0xffff00, 0xb2ff00, 0x00ff00, 0x00ffa0,
    0x00ffff, 0x008cff, 0x0000ff, 0xa500ff, 0xff00ff, 0xff0098, 0xff5959,
    0xffb459, 0xffff71, 0xcfff60, 0x6fff6f, 0x65ffc9, 0x6dffff, 0x59b4ff,
    0x5959ff, 0xc459ff, 0xff66ff, 0xff59bc, 0xff9c9c, 0xffd39c, 0xffff9c,
    0xe2ff9c, 0x9cff9c, 0x9cffdb, 0x9cffff, 0x9cd3ff, 0x9c9cff, 0xdc9cff,
    0xff9cff, 0xff94d3, 0x000000, 0x131313, 0x282828, 0x363636, 0x4d4d4d,
    0x656565, 0x818181, 0x9f9f9f, 0xbcbcbc, 0xe2e2e2, 0xffffff
)


def _irc_colour_to_hex(code: Optional[str]) -> Optional[str]:
    if code is None:
        return None
    try:
        return f'#{_colours[int(code)]:06X}'
    except (IndexError, ValueError):
        return ''


def _irc_to_html(irc_msg: str) -> Optional[str]:
    """
    Converts IRC formatting to Matrix HTML. Returns None if the message
    contains no formatting.
    """

    # Escaping quotes seems to make matrix-appservice-discord do strange things
    irc_msg = html.escape(irc_msg, quote=False)

    # If there is no formatting return immediately
    it = _formatting_re.finditer(irc_msg)
    first_match = next(it, None)
    if first_match is None:
        return None

    tags = _TagManager()
    prev_end = start = 0
    for match in itertools.chain([first_match], it):
        start = match.start()
        tags.write(irc_msg[prev_end:start])
        char = irc_msg[start]
        if char in _html_tags:
            tags.toggle(_html_tags[char])
        elif char == '\x03':
            fg = _irc_colour_to_hex(match.group(1))
            bg = _irc_colour_to_hex(match.group(2))
            # If this is a plain \x03 then reset colours
            if fg is None and bg is None:
                fg = bg = ''
            tags.set_colours(fg=fg, bg=bg)
        elif char == '\x04':
            fg = match.group(3)
            bg = match.group(4)
            if fg is None and bg is None:
                fg = bg = ''
            tags.set_colours(fg=fg and '#' + fg.upper(),
                             bg=bg and '#' + bg.upper())
        elif char == '\n':
            tags.text.append('<br>')
        elif char == '\x16':
            tags.reverse_colours = not tags.reverse_colours
            tags.set_colours()
        elif char == '\x0f':
            tags.fg = tags.bg = None
            tags.tags.clear()
        prev_end = match.end()

    tags.write(irc_msg[prev_end:])
    tags.tags.clear()
    tags.write_tags()
    return ''.join(tags.text).replace('\n', '<br>')


# This simple space collapsing regex "collapses" newlines as well
# _space_collapse_re = re.compile(r'[ \t\r\n]+')
_colour_hex_re = re.compile(r'^#[0-9a-fA-F]{6}$')


class _UnknownTagError(Exception):
    pass


class _MatrixHTMLParser(html.parser.HTMLParser):
    irc_codes = {tag: irc_code for irc_code, tag in _html_tags.items()}
    irc_codes['b'] = irc_codes['strong']
    irc_codes['i'] = irc_codes['em']
    irc_codes['br'] = '\n'

    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []
        self.in_reply = 0

    def handle_starttag(self, tag: str,
                        attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag in ('mx-reply', 'script'):
            self.in_reply += 1
        elif self.in_reply:
            return
        elif tag in self.irc_codes:
            self.text.append(self.irc_codes[tag])
        elif tag != 'font':
            # Give up trying to parse the HTML and use the fallback
            raise _UnknownTagError(tag)

    def handle_endtag(self, tag: str) -> None:
        if self.in_reply:
            if tag in ('mx-reply', 'script'):
                self.in_reply -= 1
            return
        if tag in self.irc_codes:
            self.text.append(self.irc_codes[tag])
        elif tag != 'font':
            raise _UnknownTagError(tag)

    def handle_data(self, data: str) -> None:
        if not self.in_reply:
            self.text.append(data)


def _matrix_html_to_irc(content: _Event) -> tuple[str, bool]:
    if content.format == 'org.matrix.custom.html':
        try:
            parser = _MatrixHTMLParser()
            parser.feed(content.formatted_body[str])
            # return _space_collapse_re.sub(' ', ''.join(parser.text)), True
            return ''.join(parser.text), True
        except _UnknownTagError:
            # This is okay, just use the fallback text
            pass

    return content.body[str], False


class _InvalidEventError(Exception):
    pass


_T = TypeVar('_T')
_T2 = TypeVar('_T2')


class _Event:
    """
    Event content is supposed to be considered untrusted and types must be
    validated.

    Usage:
    event = _Event(event_dict)

    msgtype1: str = event.content.msgtype[str]
    msgtype2: Optional[str] = event.content.msgtype.get(str)
    msgtype3: str = event.content.msgtype.get(str, 'default')

    assert event.content.msgtype == '<msgtype>'
    assert 'msgtype' in event.content
    assert event.content.non.existent.object == None

    assert event.content.m_test == '<Value of m.test>'
    """

    __slots__ = ('_raw', '__dict__')

    def __init__(self, raw: Any) -> None:
        self._raw = raw

    def __getattr__(self, attr: str) -> _Event:
        if isinstance(self._raw, dict):
            obj = self._raw.get(
                'm.' + attr[2:] if attr.startswith('m_') else attr
            )
        else:
            obj = None
        res = _Event(obj)

        # Cache the newly created object.
        self.__dict__[attr] = res
        return res

    def __getitem__(self, result_type: type[_T]) -> _T:
        if result_type is float and isinstance(self._raw, (int, float)):
            return self._raw  # type: ignore
        elif result_type is Any or isinstance(self._raw, result_type):
            return self._raw

        raise _InvalidEventError

    def __contains__(self, key: str) -> bool:
        return isinstance(self._raw, dict) and key in self._raw

    def __eq__(self, other: Any) -> bool:
        return self._raw == other

    @overload
    def get(self, result_type: type[_T]) -> Optional[_T]:
        ...

    @overload
    def get(self, result_type: type[_T], default: _T2) -> _T | _T2:
        ...

    def get(self, result_type, default=None):
        try:
            return self[result_type]
        except _InvalidEventError:
            return default


class Matrix(miniirc.IRC):
    connected: Optional[bool]
    msglen = 4096

    def __init__(self, ip: str, port: int = 0, nick: str = '', *args,
                 auto_connect: bool = True,
                 token: Optional[str] = None, **kwargs):
        # Cache _get_room_url
        # This is done here so that each class instance gets its own cache and
        # the cache doesn't store class instances.
        self._get_room_url = functools.lru_cache(self._get_room_url_no_cache)

        # Allow Matrix('matrix.org:443'), Matrix('matrix.org', 443), and
        # Matrix('matrix.org').
        if not port:
            try:
                new_ip, raw_port = ip.rsplit(':', 1)
                port = int(raw_port)
            except ValueError:
                port = 443
            else:
                ip = new_ip

        if token:
            self.token = token

        # Stop miniirc from trying to access the (non-existent) socket
        kwargs['ping_interval'] = kwargs['ping_timeout'] = None
        super().__init__(ip, port, nick, *args, auto_connect=False, **kwargs)
        self.__session = requests.Session()
        self.__session.headers['Authorization'] = f'Bearer {token}'
        if auto_connect:
            self.connect()

    def _url_for(self, endpoint: str) -> str:
        return f'https://{self.ip}:{self.port}/_matrix/client/v3/{endpoint}'

    def __get(self, endpoint: str, timeout: int = 5, /,
              **params: Optional[str | int]) -> Any:
        self.debug('GET', endpoint, params)
        return self.__session.get(self._url_for(endpoint), params=params,
                                  timeout=timeout).json()

    def __post(self, endpoint: str, /, **params: Any) -> Any:
        self.debug('POST', endpoint, params)
        return self.__session.post(self._url_for(endpoint), json=params,
                                   timeout=5).json()

    def __put(self, endpoint: str, /, **params: Any) -> Any:
        self.debug('PUT', endpoint, params)
        return self.__session.put(self._url_for(endpoint), json=params,
                                  timeout=5).json()

    def _get_room_url_no_cache(self, room_id: str) -> str:
        """
        Returns rooms/<room ID>.
        This is wrapped with functools.lru_cache by __init__.
        """
        if room_id.startswith('#'):
            res = self.__get(f'directory/room/{_url_quote(room_id)}')
            room_id = res.get('room_id', room_id)

        return f'rooms/{_url_quote(room_id)}'

    @functools.cached_property
    def current_nick(self) -> str:
        return self.__get('account/whoami')['user_id']

    def connect(self) -> None:
        if self.connected is not None:
            return
        with self._send_lock:
            self.active_caps = self.ircv3_caps & {
                'account-tag', 'echo-message', 'message-tags',
            }
            self.__start_time = math.floor(time.time()) * 1000
            self.debug('Starting main loop (Matrix)')
            threading.Thread(target=self._main).start()

    def disconnect(self) -> None:
        self.connected = False

    def _main(self) -> None:
        try:
            if miniirc.ver >= (2, 0, 0):
                self.handle_msg(miniirc.IRCMessage('001', ('', '', ''), {}, [
                    self.current_nick,
                    f'Welcome to Matrix {self.current_nick}'
                ]))
            else:
                self._handle('001', ('001', '001', '001'), {}, [
                    self.current_nick,
                    f':Welcome to Matrix {self.current_nick}'
                ])

            next_batch: Optional[str] = None
            while self.connected:
                req_time = time.monotonic()
                try:
                    res = self.__get('sync', 35, timeout='30000',
                                     since=next_batch)
                except (requests.ConnectionError, requests.ReadTimeout,
                        json.JSONDecodeError):
                    self.debug('Connection error when trying to fetch /sync')
                    if self.persist:
                        self.debug('Trying again in 5 seconds...')
                        time.sleep(5)
                        continue
                    return

                if self.debug_file:
                    self.debug(json.dumps(res, indent=4))
                if 'error' in res:
                    break
                next_batch = res['next_batch']
                if 'rooms' in res:
                    rooms = res['rooms']
                    self.__process_join(rooms)
                    self.__process_invite(rooms)
        finally:
            self.connected = None

    def __fire_event(self, room_id: str, event: _Event) -> None:
        try:
            # Discard events that occurred before the bot started up
            if self.__start_time > event.origin_server_ts[float]:
                return

            if f := _events.get(event.type[str]):
                f(self, room_id, event)
        except _InvalidEventError:
            if self.debug_file:
                self.debug(f'Invalid event: {event!r}')
                self.debug(traceback.format_exc())

    @_room_processor('join', 'leave')
    def __process_join(self, room_id: str, room: dict[str, Any]) -> None:
        # Joined rooms
        for raw_event in room['timeline']['events']:
            self.__fire_event(room_id, _Event(raw_event))

    @_room_processor('invite')
    def __process_invite(self, room_id: str, room: dict[str, Any]) -> None:
        # Search for the person who invited
        for raw_event in reversed(room['invite_state']['events']):
            event = _Event(raw_event)
            if (event.type == 'm.room.member' and
                    event.state_key == self.current_nick and
                    event.content.membership == 'invite'):
                self.__fire_event(room_id, event)
                break

    def quote(self, *msg: str, force: Optional[bool] = None,
              tags: Optional[dict[Any, Any]] = None) -> None:
        cmd, _, tags2, args = miniirc.ircv3_message_parser(' '.join(msg))
        if args and args[-1].startswith(':'):
            args[-1] = args[-1][1:]
        self.send(cmd, *args, force=force, tags=tags or tags2)

    def send(self, cmd: str, *args: str, force: Optional[bool] = None,
             tags: Optional[dict[Any, Any]] = None) -> None:
        cmd = cmd.upper()
        if self.debug_file:
            self.debug('>>>', cmd, *args)
        if cmd in ('PRIVMSG', 'NOTICE') and len(args) == 2:
            channel, msg = args
            if cmd == 'NOTICE':
                msgtype = 'm.notice'
            elif msg.startswith('\x01ACTION'):
                msg = msg[8:].rstrip('\x01')
                msgtype = 'm.emote'
            else:
                msgtype = 'm.text'

            params: dict[str, Any]
            if html_msg := _irc_to_html(msg):
                params = {
                    'msgtype': msgtype,
                    'body': _formatting_re.sub('', msg),
                    'format': 'org.matrix.custom.html',
                    'formatted_body': html_msg,
                }
            else:
                # No formatting
                params = {'msgtype': msgtype, 'body': msg}
            if tags:
                if tags.get('+draft/reply'):
                    params['m.relates_to'] = {
                        'm.in_reply_to': {'event_id': tags['+draft/reply']}
                    }
                self.__send_tagmsg(channel, tags)

            self.debug(
                self.__put(f'{self._get_room_url(channel)}/send/m.room.message'
                           f'/{uuid.uuid4()}', **params)
            )
        elif cmd == 'TAGMSG' and len(args) == 1 and tags:
            self.__send_tagmsg(args[0], tags)
        elif cmd == 'JOIN' and len(args) == 1:
            self.debug(self.__post(f'join/{_url_quote(args[0])}'))
        elif cmd == 'PART' and len(args) == 1:
            self.debug(self.__post(f'{self._get_room_url(args[0])}/leave'))

    def __send_tagmsg(self, channel: str, tags: dict[Any, Any]) -> None:
        if tags.get('+draft/react') and tags.get('+draft/reply'):
            react = {
                'event_id': tags['+draft/reply'],
                'key': tags['+draft/react'],
                'rel_type': 'm.annotation'
            }
            self.debug(
                self.__put(f'{self._get_room_url(channel)}/send/m.reaction'
                           f'/{uuid.uuid4()}', **{'m.relates_to': react})
            )

    if miniirc.ver >= (2, 0, 0):
        def __irc_msg(self, event: _Event, command: str, args: list[str],
                      tags: Optional[dict[str, str]] = None, *,
                      sender: Optional[str] = None) -> None:
            if sender is None:
                sender = event.sender[str]
            tags = tags or {}
            tags['msgid'] = event.event_id[str]
            tags['account'] = sender

            self.handle_msg(miniirc.IRCMessage(
                command, (sender, sender, sender), tags, args
            ))
    else:
        def __irc_msg(self, event: _Event, command: str, args: list[str],
                      tags: Optional[dict[str, str]] = None, *,
                      sender: Optional[str] = None) -> None:
            if sender is None:
                sender = event.sender[str]
            tags = tags or {}
            tags['msgid'] = event.event_id[str]
            tags['account'] = sender
            if args:
                args[-1] = ':' + args[-1]

            self._handle(command, (sender, sender, sender), tags, args)

    @_register_event('m.room.message')
    def _message_event(self, room_id: str, event: _Event) -> None:
        if ('echo-message' not in self.active_caps and
                event.sender == self.current_nick):
            return

        command = 'PRIVMSG'
        content = event.content
        tags: dict[str, str] = {}
        msg: str
        if 'url' in content:
            msg = content.url[str]
            if msg.startswith('mxc://'):
                msg = (f'https://{self.ip}:{self.port}/_matrix/media/v3/'
                       f'download/{msg[6:]}')
        else:
            msg, html_parsed_ok = _matrix_html_to_irc(content)

            if content.msgtype == 'm.emote':
                msg = f'\x01ACTION {msg}\x01'
            elif content.msgtype == 'm.notice':
                command = 'NOTICE'

        # Convert replies
        try:
            tags['+draft/reply'] = \
                content.m_relates_to.m_in_reply_to.event_id[str]
        except _InvalidEventError:
            pass
        else:
            # Remove the reply added by Element
            if (content.format == 'org.matrix.custom.html' and
                    not html_parsed_ok and msg.startswith('> ')):
                msg = msg.split('\n\n', 1)[-1]

        self.__irc_msg(event, command, [room_id, msg], tags)

    @_register_event('m.room.member')
    def _member_event(self, room_id: str, event: _Event) -> None:
        membership = event.content.membership[str]
        if membership == 'invite':
            self.__irc_msg(event, 'INVITE', [event.state_key[str], room_id])
        elif membership == 'join':
            self.__irc_msg(event, 'JOIN', [room_id],
                           sender=event.state_key[str])
        elif membership == 'leave':
            # Don't send the PART event if this is an un-invite
            if event.unsigned.prev_content.membership == 'invite':
                # This isn't a standard IRC message, Ergo sends something
                # similar but only to the client that did /uninvite and not the
                # one that was uninvited.
                self.__irc_msg(event, 'UNINVITE', [
                    event.state_key[str], room_id
                ])
            elif event.sender == event.state_key:
                self.__irc_msg(event, 'PART', [
                    room_id, event.content.reason.get(str, 'Leaving')
                ])
            else:
                self.__irc_msg(event, 'KICK', [
                    room_id, event.state_key[str],
                    event.content.reason.get(str, 'Kicked')
                ])

    @_register_event('m.room.topic')
    def _topic_event(self, room_id: str, event: _Event) -> None:
        self.__irc_msg(event, 'TOPIC', [room_id, event.content.topic[str]])

    @_register_event('m.reaction')
    def _reaction_event(self, room_id: str, event: _Event) -> None:
        relates_to = event.content.m_relates_to
        self.__irc_msg(event, 'TAGMSG', [room_id], {
            '+draft/react': relates_to.key[str],
            '+draft/reply': relates_to.event_id[str]
        })

    # Helpers
    @classmethod
    def _login(cls, homeserver: str, username: str, password: str) -> str:
        """ Logs in. Returns a new token or raises an exception. """
        matrix = cls(homeserver, auto_connect=False)
        res = matrix.__post(
            'login',
            type='m.login.password',
            identifier={'type': 'm.id.user', 'user': username},
            password=password,
        )
        if 'error' in res:
            raise ValueError(f'{res.get("errcode")}: {res.get("error")}')
        return res['access_token']

    @classmethod
    def _logout(cls, homeserver: str, token: str) -> None:
        """ Logs out / voids the specified token. """
        cls(homeserver, token=token, auto_connect=False).__post('logout')

    @classmethod
    def _logout_all(cls, homeserver: str, username: str,
                    password: str) -> None:
        """ Logs out everywhere / voids all tokens for the user. """
        token = cls.login(homeserver, username, password)
        matrix = Matrix(homeserver, token=token, auto_connect=False)
        res = matrix.__post('logout/all')
        assert 'error' not in res, res


login = Matrix._login
logout = Matrix._logout
logout_all = Matrix._logout_all
