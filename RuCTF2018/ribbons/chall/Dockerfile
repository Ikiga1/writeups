FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install cmake build-essential wget -y

COPY . /home/ribbons
RUN wget "https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-0.9.59.tar.gz"
RUN tar -zxf "libmicrohttpd-0.9.59.tar.gz"

WORKDIR libmicrohttpd-0.9.59

RUN ./configure && make && make install

WORKDIR /home/ribbons

RUN mkdir bin
RUN mkdir bin/data

WORKDIR bin

COPY ribbons /home/ribbons/bin/

CMD ./ribbons

