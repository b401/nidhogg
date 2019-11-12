FROM ubuntu:latest

RUN apt update && apt install -y \
	libpcap-dev \
	libsqlite3-0 \
	curl \
	nmap


RUN mkdir /etc/nidhogg \
	&& ln -s /usr/lib/x86_64-linux-gnu/libpcap.so /usr/lib/x86_64-linux-gnu/libpcap.so.1
COPY static /etc/nidhogg/static
COPY web/templates /etc/nidhogg/templates

COPY target/release/nidhogg /usr/bin/nidhogg

ENTRYPOINT /usr/bin/nidhogg
