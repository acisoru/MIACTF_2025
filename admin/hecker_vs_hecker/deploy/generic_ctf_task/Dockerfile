FROM ubuntu:latest

RUN useradd -m -s /bin/bash user && echo 'user:password' | chpasswd

RUN apt update && apt install -y nmap openssh-server sudo && rm -rf /var/lib/apt/lists/*

RUN mkdir /var/run/sshd && chmod 0755 /var/run/sshd

RUN echo 'PermitUserEnvironment no' >> /etc/ssh/sshd_config
RUN echo 'PermitTunnel no' >> /etc/ssh/sshd_config
RUN echo 'AllowTcpForwarding no' >> /etc/ssh/sshd_config
RUN echo 'X11Forwarding no' >> /etc/ssh/sshd_config
RUN echo 'PermitRootLogin no' >> /etc/ssh/sshd_config

RUN echo 'ALL ALL=(ALL) NOPASSWD: /usr/bin/nmap' >> /etc/sudoers

RUN echo "miactf{7yp1c4l_lp3_4641n}" > /root/flag.txt && chmod 600 /root/flag.txt

RUN chown -R user:user /home/user

EXPOSE 22

CMD ["/bin/bash", "-c", "ssh-keygen -A && /usr/sbin/sshd -D"]