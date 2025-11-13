FROM python:2.7

WORKDIR /app

COPY . /app

RUN pip install -r requirements.txt
RUN openssl req -new -x509 -key key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=WA/L=Seattle/O=AstarteLabs/OU=waaagh/CN=None"


CMD ["python", "mogui.py"]