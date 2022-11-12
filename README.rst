ConfidentialQUIC
=======

What is ``ConfidentialQUIC``?
--------------------
``ConfidentialQUIC`` is a proof of concept demo for natively anonymous internet connections with respect to the network. It is built on top of the ``aioquic`` library. The demo is located in the examples/conf_test4 directory. As of November 11th 2022 this demo does not use the final design but a simpler and unencrypted model. To view this newer model and how the concept works view the concept.rtf document.

How to run the demo
--------------------
1) This demo relies on IPv6 and so Docker is used to manage a virtual IPv6 enabled network on your system. Much easier than acquiring from your ISP a real IPv6 address. I am using Docker Desktop on Windows. In Docker desktop you will need to edit the Docker engine config in Settings>Docker Engine. In the config add the two key value pairs:
::

    {
      ...
      "fixed-cidr-v6": "2001:db1:1::/64",
      "ipv6": true,
      ...
    }

You may have to restart your docker engine for these changes to take effect. The fixed-cidr-v6 field does not have to be the value in the above code block but if you change it the ip-addresses of the client and server docker images of the demo will have to be changed in the docker files as well.

2) Create the ipv6 network for the containers to communicate over:
::

 > docker network create --subnet=172.16.2.0/24 --gateway=172.16.2.1 --ipv6 --subnet=2001:db8:1::/64 --opt com.docker.network.bridge.enable_ip_masquerade=true test-net

3) Next you need to enter the examples/conf_test4 folder and perform the following commands to build and start the demo:
::

    > docker-compose build
    > docker-compose start
 
This should complete the demo of performing two requests from the client to the server using on the header of the IP packets a false source address.
 
aioquic setup
-------
The below text is the README from the aioquic repository. I left it because it is needed to setup aioquic for the ConfidentialQUIC demo.
 
 
aioquic
=======

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |tests| |codecov| |black|

.. |rtd| image:: https://readthedocs.org/projects/aioquic/badge/?version=latest
    :target: https://aioquic.readthedocs.io/

.. |pypi-v| image:: https://img.shields.io/pypi/v/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |pypi-l| image:: https://img.shields.io/pypi/l/aioquic.svg
    :target: https://pypi.python.org/pypi/aioquic

.. |tests| image:: https://github.com/aiortc/aioquic/workflows/tests/badge.svg
    :target: https://github.com/aiortc/aioquic/actions

.. |codecov| image:: https://img.shields.io/codecov/c/github/aiortc/aioquic.svg
    :target: https://codecov.io/gh/aiortc/aioquic

.. |black| image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/python/black

What is ``aioquic``?
--------------------

``aioquic`` is a library for the QUIC network protocol in Python. It features
a minimal TLS 1.3 implementation, a QUIC stack and an HTTP/3 stack.

QUIC was standardised in RFC 9000, but HTTP/3 standardisation is still ongoing.
``aioquic`` closely tracks the specification drafts and is regularly tested for
interoperability against other `QUIC implementations`_.

To learn more about ``aioquic`` please `read the documentation`_.

Why should I use ``aioquic``?
-----------------------------

``aioquic`` has been designed to be embedded into Python client and server
libraries wishing to support QUIC and / or HTTP/3. The goal is to provide a
common codebase for Python libraries in the hope of avoiding duplicated effort.

Both the QUIC and the HTTP/3 APIs follow the "bring your own I/O" pattern,
leaving actual I/O operations to the API user. This approach has a number of
advantages including making the code testable and allowing integration with
different concurrency models.

Features
--------

- QUIC stack conforming with RFC 9000
- HTTP/3 stack conforming with draft-ietf-quic-http-34
- minimal TLS 1.3 implementation
- IPv4 and IPv6 support
- connection migration and NAT rebinding
- logging TLS traffic secrets
- logging QUIC events in QLOG format
- HTTP/3 server push support

Requirements
------------

``aioquic`` requires Python 3.7 or better, and the OpenSSL development headers.

Linux
.....

On Debian/Ubuntu run:

.. code-block:: console

   $ sudo apt install libssl-dev python3-dev

On Alpine Linux you will also need the following:

.. code-block:: console

   $ sudo apt install bsd-compat-headers libffi-dev

OS X
....

On OS X run:

.. code-block:: console

   $ brew install openssl

You will need to set some environment variables to link against OpenSSL:

.. code-block:: console

   $ export CFLAGS=-I/usr/local/opt/openssl/include
   $ export LDFLAGS=-L/usr/local/opt/openssl/lib

Windows
.......

On Windows the easiest way to install OpenSSL is to use `Chocolatey`_.

.. code-block:: console

   > choco install openssl

You will need to set some environment variables to link against OpenSSL:

.. code-block:: console

  > $Env:INCLUDE = "C:\Progra~1\OpenSSL-Win64\include"
  > $Env:LIB = "C:\Progra~1\OpenSSL-Win64\lib"

Running the examples
--------------------

`aioquic` comes with a number of examples illustrating various QUIC usecases.

You can browse these examples here: https://github.com/aiortc/aioquic/tree/main/examples

License
-------

``aioquic`` is released under the `BSD license`_.

.. _read the documentation: https://aioquic.readthedocs.io/en/latest/
.. _QUIC implementations: https://github.com/quicwg/base-drafts/wiki/Implementations
.. _cryptography: https://cryptography.io/
.. _Chocolatey: https://chocolatey.org/
.. _BSD license: https://aioquic.readthedocs.io/en/latest/license.html
