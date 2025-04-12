FROM ubuntu:20.04

RUN apt-get -y update
RUN apt-get -y install socat

RUN useradd -m ctf

USER ctf
WORKDIR /home/ctf
COPY awesome_asm  /home/ctf
COPY flag  /home/ctf
EXPOSE 17171
CMD socat tcp-listen:17171,reuseaddr,fork exec:"./awesome_asm"
