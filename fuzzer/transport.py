"""
    Raw HTTP/1.1 transport.

    Default HTTP clients normalize the URI before sending the request. 
    So it is important in a fuzzer to send the raw mutated URI to the target, 
    without any normalization - byte by byte.
"""
from __future__ import annotations
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit


@dataclass
class RawResponse:
    '''
        Contains the raw HTTP response from the target, including status code, reason,
        headers, and body. The headers are stored in a case-insensitive dictionary.
    '''
    res_status: int
    res_reason: str
    res_headers: dict[str, str]
    res_body: bytes

    def header(self, name: str, default: str = "") -> str:
        ''''
            Get a header value by name, case-insensitive.
        '''
        name = name.strip().lower()
        return self.res_headers.get(name, default)

    @property
    def text(self) -> str:
        '''
            Get the response body as a UTF-8 string, replacing invalid bytes.
        '''
        return self.res_body.decode("utf-8", errors="replace")


@dataclass
class RawRequest:
    ''''
        Contains the raw HTTP request to be sent to the target.
    '''
    base_url: str
    raw_target: str # mutated target path
    method: str = "GET"
    extra_headers: dict[str, str] = field(default_factory=dict)
    timeout: float = 5.0


def send_raw(req: RawRequest) -> RawResponse:
    '''
        Send a raw HTTP request to the target and return the raw response.
    '''

    parts = urlsplit(req.base_url)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if parts.scheme == "https" else 80)
    use_tls = parts.scheme == "https"

    target = req.raw_target if req.raw_target.startswith("/") else "/" + req.raw_target

    headers = {
        "Host": parts.netloc,
        "User-Agent": "pcfuzz/0.1",
        "Accept": "*/*",
        "Connection": "close",
    }
    headers.update(req.extra_headers)

    request = f"{req.method} {target} HTTP/1.1\r\n"

    # build the request head with headers
    head = request + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n"
    head = head.encode("latin-1")

    conn_socket = socket.create_connection((host, port), timeout=req.timeout)
    try:
        # wrap the socket with SSL if needed
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn_socket = ctx.wrap_socket(conn_socket, server_hostname=host)
        
        # send the request head and read the response
        conn_socket.sendall(head)
        raw_response = _read_response(conn_socket, req.timeout)
    finally:
        conn_socket.close()

    return _parse_response(raw_response)


def _read_response(sock: socket.socket, timeout: float) -> bytes:
    '''
        Read the raw HTTP response from the previously opened socket until 
            the connection is closed or a timeout occurs.
    '''

    sock.settimeout(timeout)
    res_chunks: list[bytes] = []
    try:
        while True:
            byte = sock.recv(65536)
            if not byte:
                break
            
            res_chunks.append(byte)
    except (socket.timeout, OSError):
        pass
    return b"".join(res_chunks)


def _parse_response(raw: bytes) -> RawResponse:
    '''
        Parse the raw HTTP response into a RawResponse object.
    '''
    if not raw:
        return RawResponse(0, "NO_RESPONSE", {}, b"")

    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", "replace") # e.g. HTTP/1.1 200 OK
    bits = status_line.split(" ", 2) # e.g. ["HTTP/1.1", "200", "OK"]

    status = int(bits[1]) if len(bits) > 1 and bits[1].isdigit() else 0
    reason = bits[2] if len(bits) > 2 else ""

    headers: dict[str, str] = {} 
    for ln in lines[1:]:
        k, _, v = ln.decode("latin-1", "replace").partition(":")
        if k:
            headers[k.strip().lower()] = v.strip()

    # If the response is chunked, dechunk it to get the full body.
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = _dechunk_response(body)

    return RawResponse(status, reason, headers, body)


def _dechunk_response(body: bytes) -> bytes:
    '''
        Dechunk a chunked HTTP response body.
    '''
    out = bytearray()
    while body:
        size_line, _, rest = body.partition(b"\r\n")
        try:
            size = int(size_line.strip(), 16)
        except ValueError:
            break
        if size == 0:
            break
        out += rest[:size]
        body = rest[size + 2:]
    return bytes(out)
