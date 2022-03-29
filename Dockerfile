FROM python:3

ADD blockcheck.py /

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

CMD [ "python", "./blockcheck.py" ]

