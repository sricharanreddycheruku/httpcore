import pytest
from socksio.exceptions import ProtocolError

import httpcore


class SOCKS5MockStream(httpcore.AsyncMockStream):
    async def read(self, max_bytes, timeout=None):
        data = await super().read(max_bytes, timeout)
        if len(data) > max_bytes:
            self._buffer.insert(0, data[max_bytes:])
            return data[:max_bytes]
        return data


class SOCKS5MockBackend(httpcore.AsyncMockBackend):
    async def connect_tcp(self, *args, **kwargs):
        return SOCKS5MockStream(list(self._buffer))


@pytest.mark.anyio
@pytest.mark.parametrize("fragment_size", [1, 2, 8, 4096])
@pytest.mark.parametrize("auth", [None, (b"username", b"password")])
@pytest.mark.parametrize(
    "reply",
    [
        b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50",
        b"\x05\x00\x00\x04" + b"\x00" * 15 + b"\x01\x00\x50",
        b"\x05\x00\x00\x03\x0bexample.com\x00\x50",
    ],
    ids=["ipv4", "ipv6", "domain"],
)
async def test_socks5_fragmented_replies(fragment_size, auth, reply):
    replies = [b"\x05\x00"] if auth is None else [b"\x05\x02", b"\x01\x00"]
    replies.append(reply)
    fragments = [
        packet[offset : offset + fragment_size]
        for packet in replies
        for offset in range(0, len(packet), fragment_size)
    ]
    backend = SOCKS5MockBackend(
        fragments + [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]
    )
    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:1080", auth=auth),
        network_backend=backend,
    ) as pool:
        response = await pool.request("GET", "http://example.com")

    assert response.status == 200
    assert response.content == b"hello"


@pytest.mark.anyio
@pytest.mark.parametrize(
    "replies, auth",
    [
        ([], None),
        ([b"\x05"], None),
        ([b"\x05\x02", b"\x01"], (b"username", b"password")),
        ([b"\x05\x00", b"\x05\x00\x00"], None),
        ([b"\x05\x00", b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00"], None),
        ([b"\x05\x00", b"\x05\x00\x00\x04" + b"\x00" * 15], None),
        ([b"\x05\x00", b"\x05\x00\x00\x03"], None),
        ([b"\x05\x00", b"\x05\x00\x00\x03\x0bexample"], None),
    ],
    ids=[
        "empty-auth",
        "partial-auth",
        "partial-password",
        "partial-header",
        "partial-ipv4-port",
        "partial-ipv6-address",
        "missing-domain-length",
        "partial-domain",
    ],
)
async def test_socks5_disconnected_during_reply(replies, auth):
    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:1080", auth=auth),
        network_backend=SOCKS5MockBackend(replies),
    ) as pool:
        with pytest.raises(httpcore.ProxyError, match="disconnected during SOCKS5"):
            await pool.request("GET", "http://example.com")


@pytest.mark.anyio
@pytest.mark.parametrize("auth", [None, (b"username", b"password")])
async def test_socks5_reply_does_not_consume_http_response(auth):
    replies = [b"\x05\x00"] if auth is None else [b"\x05\x02", b"\x01\x00"]
    replies.append(
        b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x50"
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
    )
    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:1080", auth=auth),
        network_backend=SOCKS5MockBackend(replies),
    ) as pool:
        response = await pool.request("GET", "http://example.com")

    assert response.status == 200
    assert response.content == b"hello"


@pytest.mark.anyio
@pytest.mark.parametrize("header", [b"\x04\x00\x00\x01", b"\x05\x00\x00\xff"])
async def test_socks5_invalid_reply_header(header):
    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:1080"),
        network_backend=SOCKS5MockBackend([b"\x05\x00", header]),
    ) as pool:
        with pytest.raises(ProtocolError, match="Malformed reply"):
            await pool.request("GET", "http://example.com")


@pytest.mark.anyio
async def test_socks5_request():
    """
    Send an HTTP request via a SOCKS proxy.
    """
    network_backend = httpcore.AsyncMockBackend(
        [
            # The initial socks CONNECT
            #   v5 NOAUTH
            b"\x05\x00",
            #   v5 SUC RSV IP4 127  .0  .0  .1     :80
            b"\x05\x00\x00\x01\xff\x00\x00\x01\x00\x50",
            # The actual response from the remote server
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:8080/"),
        network_backend=network_backend,
    ) as proxy:
        # Sending an intial request, which once complete will return to the pool, IDLE.
        async with proxy.stream("GET", "https://example.com/") as response:
            info = [repr(c) for c in proxy.connections]
            assert info == [
                "<AsyncSocks5Connection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>"
            ]
            await response.aread()

        assert response.status == 200
        assert response.content == b"Hello, world!"
        info = [repr(c) for c in proxy.connections]
        assert info == [
            "<AsyncSocks5Connection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]
        assert proxy.connections[0].is_idle()
        assert proxy.connections[0].is_available()
        assert not proxy.connections[0].is_closed()

        # A connection on a tunneled proxy can only handle HTTPS requests to the same origin.
        assert not proxy.connections[0].can_handle_request(
            httpcore.Origin(b"http", b"example.com", 80)
        )
        assert not proxy.connections[0].can_handle_request(
            httpcore.Origin(b"http", b"other.com", 80)
        )
        assert proxy.connections[0].can_handle_request(
            httpcore.Origin(b"https", b"example.com", 443)
        )
        assert not proxy.connections[0].can_handle_request(
            httpcore.Origin(b"https", b"other.com", 443)
        )


@pytest.mark.anyio
async def test_authenticated_socks5_request():
    """
    Send an HTTP request via a SOCKS proxy.
    """
    network_backend = httpcore.AsyncMockBackend(
        [
            # The initial socks CONNECT
            #   v5 USERNAME/PASSWORD
            b"\x05\x02",
            #   v1 VALID USERNAME/PASSWORD
            b"\x01\x00",
            #   v5 SUC RSV IP4 127  .0  .0  .1     :80
            b"\x05\x00\x00\x01\xff\x00\x00\x01\x00\x50",
            # The actual response from the remote server
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: plain/text\r\n",
            b"Content-Length: 13\r\n",
            b"\r\n",
            b"Hello, world!",
        ]
    )

    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy(
            url="socks5://localhost:8080/",
            auth=(b"username", b"password"),
        ),
        network_backend=network_backend,
    ) as proxy:
        # Sending an intial request, which once complete will return to the pool, IDLE.
        async with proxy.stream("GET", "https://example.com/") as response:
            info = [repr(c) for c in proxy.connections]
            assert info == [
                "<AsyncSocks5Connection ['https://example.com:443', HTTP/1.1, ACTIVE, Request Count: 1]>"
            ]
            await response.aread()

        assert response.status == 200
        assert response.content == b"Hello, world!"
        info = [repr(c) for c in proxy.connections]
        assert info == [
            "<AsyncSocks5Connection ['https://example.com:443', HTTP/1.1, IDLE, Request Count: 1]>"
        ]
        assert proxy.connections[0].is_idle()
        assert proxy.connections[0].is_available()
        assert not proxy.connections[0].is_closed()


@pytest.mark.anyio
async def test_socks5_request_connect_failed():
    """
    Attempt to send an HTTP request via a SOCKS proxy, resulting in a connect failure.
    """
    network_backend = httpcore.AsyncMockBackend(
        [
            # The initial socks CONNECT
            #   v5 NOAUTH
            b"\x05\x00",
            #   v5  NO RSV IP4   0  .0  .0  .0     :00
            b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00",
        ]
    )

    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:8080/"),
        network_backend=network_backend,
    ) as proxy:
        # Sending a request, which the proxy rejects
        with pytest.raises(httpcore.ProxyError) as exc_info:
            await proxy.request("GET", "https://example.com/")
        assert (
            str(exc_info.value) == "Proxy Server could not connect: Connection refused."
        )

        assert not proxy.connections


@pytest.mark.anyio
async def test_socks5_request_failed_to_provide_auth():
    """
    Attempt to send an HTTP request via an authenticated SOCKS proxy,
    without providing authentication credentials.
    """
    network_backend = httpcore.AsyncMockBackend(
        [
            #   v5 USERNAME/PASSWORD
            b"\x05\x02",
        ]
    )

    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy("socks5://localhost:8080/"),
        network_backend=network_backend,
    ) as proxy:
        # Sending a request, which the proxy rejects
        with pytest.raises(httpcore.ProxyError) as exc_info:
            await proxy.request("GET", "https://example.com/")
        assert (
            str(exc_info.value)
            == "Requested NO AUTHENTICATION REQUIRED from proxy server, but got USERNAME/PASSWORD."
        )

        assert not proxy.connections


@pytest.mark.anyio
async def test_socks5_request_incorrect_auth():
    """
    Attempt to send an HTTP request via an authenticated SOCKS proxy,
    wit incorrect authentication credentials.
    """
    network_backend = httpcore.AsyncMockBackend(
        [
            #   v5 USERNAME/PASSWORD
            b"\x05\x02",
            #   v1 INVALID USERNAME/PASSWORD
            b"\x01\x01",
        ]
    )

    async with httpcore.AsyncConnectionPool(
        proxy=httpcore.Proxy(
            url="socks5://localhost:8080/",
            auth=(b"invalid", b"invalid"),
        ),
        network_backend=network_backend,
    ) as proxy:
        # Sending a request, which the proxy rejects
        with pytest.raises(httpcore.ProxyError) as exc_info:
            await proxy.request("GET", "https://example.com/")
        assert str(exc_info.value) == "Invalid username/password"

        assert not proxy.connections
