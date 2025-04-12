FROM ubuntu:24.04

RUN apt-get -y update
RUN apt-get -y install socat

RUN useradd -m ctf

USER ctf
WORKDIR /home/ctf
COPY more_notes  /home/ctf
COPY flag  /home/ctf
EXPOSE 37373
CMD socat tcp-listen:37373,reuseaddr,fork exec:"./more_notes"
