FROM alpine:latest

RUN apk add --no-cache openssh-server shadow sudo strace && \
    ssh-keygen -A && \
    adduser -D -h /home/user -s /bin/sh user \
    && echo "user:password" | chpasswd \
    && mkdir -p /home/user/.ssh \
    && chown -R root:root /home/user \
    && chmod 555 /home/user \
    && chmod 755 /home/user/.ssh \
    && apk del shadow apk-tools \
    && rm -f \
      /usr/bin/ssh /usr/bin/scp /usr/bin/sftp \
      /usr/bin/wget /usr/bin/curl /usr/bin/nc \
      /usr/bin/nslookup /usr/bin/ftp \
      /usr/bin/rsync

# Allow user to run /usr/bin/od as root via sudo
RUN mkdir -p /etc/sudoers.d && \
    echo 'user ALL=(ALL) NOPASSWD: /usr/bin/strace' > /etc/sudoers.d/strace && \
    chmod 0440 /etc/sudoers.d/strace

COPY ./scripts/ /home/user/

RUN sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^Subsystem sftp.*/Subsystem sftp \/bin\/false/' /etc/ssh/sshd_config \
    && echo "MaxSessions 1000" >> /etc/ssh/sshd_config \
    && echo "MaxStartups 1000" >> /etc/ssh/sshd_config \
    && echo "Warning: Your server got hacked! Try to find the real flag! You'll NEVER find it!" > /etc/motd

RUN touch /home/user/.profile \
    && echo "export HISTFILE=/dev/null" >> /home/user/.profile \
    && echo "export HISTSIZE=0" >> /home/user/.profile \
    && echo "export PS1='\\[\\e[1;31m\\]SUS-TEM\\[\\e[0m\\]> '" >> /home/user/.profile 

RUN chmod 700 /home/user/folder_13/subfolder_18/.service-restart_1866.sh

EXPOSE 22

CMD ["sh", "-c", "/home/user/folder_13/subfolder_18/.service-restart_1866.sh & /usr/sbin/sshd -D -e"]