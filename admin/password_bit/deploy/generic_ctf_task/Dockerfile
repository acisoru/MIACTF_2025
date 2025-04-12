FROM ubuntu:latest

RUN useradd -m -s /bin/bash user && echo 'user:password' | chpasswd

RUN apt update && apt install -y openssh-server python3 sudo && rm -rf /var/lib/apt/lists/*

RUN mkdir /var/run/sshd && chmod 0755 /var/run/sshd

RUN ssh-keygen -A

COPY banner.py /tmp/banner.py
RUN python3 /tmp/banner.py && mv /tmp/banner.sh /etc/banner.sh && rm /tmp/banner.py

COPY shell.sh /usr/local/bin/shell-wrapper
COPY forbidden.txt /etc/forbidden.txt
RUN chmod +x /usr/local/bin/shell-wrapper

COPY main /home/user/main
RUN chmod +x /home/user/main && chown user:user /home/user/main

RUN echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config
RUN echo 'PermitTunnel no' >> /etc/ssh/sshd_config
RUN echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config
RUN echo 'X11Forwarding no' >> /etc/ssh/sshd_config
RUN echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

RUN echo 'user ALL=(ALL) NOPASSWD: /usr/local/bin/shell-wrapper' >> /etc/sudoers
RUN echo 'Match User user\n  ForceCommand /usr/local/bin/shell-wrapper' >> /etc/ssh/sshd_config

RUN chown -R user:user /home/user

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
