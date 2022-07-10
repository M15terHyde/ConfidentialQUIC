FROM python:3.10.4
RUN apt update; apt upgrade -y; apt install netcat -y; apt install iproute2 -y; apt install iputils-ping -y

COPY . /confidentialSocket
RUN pip install --no-cache-dir --upgrade -r /confidentialSocket/requirements.txt

RUN chmod u+x /confidentialSocket/test2/client_startup.sh

WORKDIR /confidentialSocket/test2/
ENV PYTHONPATH=/
CMD ["./client_startup.sh"]
