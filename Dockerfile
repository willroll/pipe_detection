FROM python:3.12-slim

WORKDIR /app

# openssl CLI for the self-signed cert generated below (not in the slim image).
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

# Generate the key AND the self-signed cert in one step. (The old command used
# `-key key.pem`, which requires a pre-existing key the repo never shipped, so
# the build failed. `-newkey ... -keyout` creates the key here.)
RUN openssl req -newkey rsa:2048 -nodes -keyout key.pem \
    -x509 -sha256 -days 3650 -out cert.pem \
    -subj "/C=XX/ST=WA/L=Seattle/O=AstarteLabs/OU=waaagh/CN=localhost"

EXPOSE 5555

CMD ["python", "mogui.py"]
