Scenario
========
Strange activity has been detected originating from the rao411 server, but our
team has been unable to understand from where the commands are coming from, we
need your help.

This machine is an up-to-date Ubuntu 17.04 server with the original kernel and
secure boot signed with the Microsoft key, so we know no one tampered with the
kernel. We also audited our remote connections and the commands do not seem to
come from SSH, help us understand how the root commands are being sent and
executed.

Server: 9000:470:b2b5:cafe:5054:ff:feb1:dd21
Username: raops
Password: raops

Copying
=======
The core of the code comes from Jesper Dangaard Brouer's repository:
https://github.com/netoptimizer/prototype-kernel

Everything is GPLv2
