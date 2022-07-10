FROM python:3.10.4
RUN apt update; apt upgrade -y; apt install netcat -y; apt install iproute2 -y; apt install iputils-ping -y


COPY . /aioquic
RUN pip install --no-cache-dir --upgrade -r /aioquic/examples/control_test/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /aioquic/requirements/doc.txt

RUN chmod u+x /aioquic/examples/control_test/client_startup.sh

WORKDIR /aioquic
RUN pip install -e .
ENV PYTHONPATH=/aioquic
#:/aioquic/src:/aioquic/src/aioquic
CMD ["./examples/control_test/client_startup.sh"]
