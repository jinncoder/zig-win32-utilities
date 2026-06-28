#!/usr/bin/env python3

import argparse
import socket
import struct
from pathlib import PosixPath

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dll",
        default="lol.dll",
        help="The DLL to send",
    )
    parser.add_argument(
        "--bind",
        "-b",
        default="127.0.0.1:55555",
        help="Specify alternate bind address " "[default: all interfaces]",
    )

    args = parser.parse_args()
    args.dll = PosixPath(args.dll)

    if not args.dll.exists():
        print(f"[!] Failed to locate {args.dll}")
        exit(1)

    args.dll = args.dll.read_bytes()

    parts = args.bind.split(':')
    if len(parts) != 2:
        print(f"[!] Use IP:PORT for --bind vs. {args.bind}")
        exit(2)

    host = str(parts[0])
    port = int(parts[1])

    print(f"[+] Starting Listener on {host}:{port}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)  # one client at a time

    print(f"[+] Using DLL with size {len(args.dll)}")

    while True:
        stream, address = server.accept()
        print(f"[+] Connection from {address}")

        stream.sendall(struct.pack("!I", len(args.dll)))
        stream.sendall(args.dll)

        stream.shutdown(socket.SHUT_RDWR)
        stream.close()
        print(f"[+] Connection closed {address}")
