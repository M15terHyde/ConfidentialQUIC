FROM python:3.10.4
#RUN apt update; apt upgrade -y;

COPY . /confidentialSocket
RUN pip install --no-cache-dir --upgrade -r /confidentialSocket/requirements.txt

RUN chmod u+x /confidentialSocket/test1/server_startup.sh

WORKDIR /confidentialSocket/test1/
ENV PYTHONPATH=/
CMD ["./server_startup.sh"]
