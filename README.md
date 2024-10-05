# miniirc_matrix

[![Available on PyPI.](https://img.shields.io/pypi/v/miniirc-matrix.svg)](https://pypi.org/project/miniirc-matrix/)

A wrapper for miniirc ([GitHub], [GitLab]) to allow bots or clients made in
miniirc to join Matrix rooms with minimal code changes. Requires Python 3.8 or
later.

## How to use

To use miniirc_matrix, you already need to know how to use miniirc ([GitHub],
[GitLab]). Instead of creating a `miniirc.IRC` object, however, you need to
use `miniirc_matrix.Matrix`.

 - `ip` is the address of the Matrix homeserver.
 - `port` is optional and will default to 443 if not specified and if `ip`
    doesn't have a port.
 - There is a `token` keyword argument that must contain the Matrix token.

Example: `irc = miniirc_matrix.Matrix('matrix.org:443', token='my_token')`

Channel names are currently room IDs and start with `!`. You may use a Matrix
room alias (for example `#matrix:matrix.org`) in place of a room ID, however.
Hopefully one day alias support will be added so that channel names can
correspond to alias names.

Formatting is translated to and from Matrix's custom HTML format. Note that
colours are not supported in incoming messages, although they mostly work in
outgoing messages.

[GitHub]: https://github.com/luk3yx/miniirc
[GitLab]: https://gitlab.com/luk3yx/miniirc

## Obtaining a token

You must obtain a token to use miniirc_matrix. You can do this with
`miniirc_matrix.login(homeserver_address, username, password)`.

There is also `miniirc_matrix.logout(homeserver_address, token)` and
`miniirc_matrix.logout_all(homeserver_address, username, password)` if you wish
to invalidate your token.

## Supported commands

The `PRIVMSG` (including `CTCP ACTION`/`irc.me`), `NOTICE`, `TAGMSG`, `JOIN`,
and `PART` commands should work as expected.

Note that events sent before the client connects to Matrix are ignored. Your
system must have an accurate clock for this to work properly.

## Downloading media

Matrix has recently started to require authentication for media endpoints. By
default, miniirc_matrix now translates media files into MXC URLs. It does,
however, have a built-in HTTP proxy (disabled by default, see below).

### Proxying requests (experimental)

**Warning: I don't know how secure this is, it uses Python's `http.server`**

If you want to convert media to a normal URL, for example for use with relay
bots or code that expects normal links, you can provide a `media_proxy_port`
argument to miniirc_matrix.Matrix.

```py
miniirc_matrix.Matrix('example.com', token='my_token',
                      media_proxy_port=8080)
```

This will start a HTTP server on `http://127.0.0.1:8080` to listen for ports.
The server only listens on localhost.

To expose this to the public, you must use a reverse proxy, and should set up
caching and some kind of rate limiting to prevent abuse. You can set the
`media_proxy_url` keyword argument to the public proxy URL.

A HMAC is created based on a random key and URL to prevent using the proxy to
fetch arbitrary attachment URLs. To make this value consistent across restarts,
pass a bytes value to the `media_proxy_key` keyword argument.

## Installation

You can install `miniirc_matrix` with `pip install miniirc_matrix`.
