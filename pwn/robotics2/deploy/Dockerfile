FROM ubuntu:24.04@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782

RUN apt-get -y update && apt-get -y install socat

COPY flag.txt /
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

RUN useradd -m ctf

USER ctf
WORKDIR /home/ctf

COPY robotics2 .

CMD ["socat", "tcp-l:11331,reuseaddr,fork", "exec:./robotics2"]
