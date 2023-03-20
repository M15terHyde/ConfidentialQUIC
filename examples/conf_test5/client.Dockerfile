#python:3.10.4
FROM conf-quic-base:latest
#RUN apt update; apt upgrade -y; apt install netcat -y; apt install iproute2 -y; apt install iputils-ping -y

#RUN mkdir /qlogstore
VOLUME [ "/qlogstore" ]
RUN chmod u+w /qlogstore

COPY . /aioquic
#RUN pip install --no-cache-dir --upgrade -r /aioquic/examples/conf_test5/requirements.txt
#RUN pip install --no-cache-dir --upgrade -r /aioquic/requirements/doc.txt

RUN chmod u+x /aioquic/examples/conf_test5/client_startup.sh

WORKDIR /aioquic
RUN pip install -e .
ENV PYTHONPATH=/aioquic
#:/aioquic/src:/aioquic/src/aioquic
CMD ["./examples/conf_test5/client_startup.sh"]
