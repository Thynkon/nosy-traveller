#!/usr/bin/env python3

import argparse
import socket
import syslog


def log_message(message, facility):
    print(message)
    syslog.syslog(facility, message)


def scan_target(address, ports):
    open_ports = []

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((address, ports))
        except ConnectionError:
            pass
        else:
            open_ports.append(ports)

        return open_ports


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="A simple port scanner")
    parser.add_argument("-a", "--address",
                        help="target's ip address", required=True)
    parser.add_argument("-p", "--ports",
                        help="target's port")
    args = parser.parse_args()

    address = args.address
    ports = args.ports

    # Connect to syslog server
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

    # Scan ports
    log_message(f"Scanning {address}", syslog.LOG_INFO)
    open_ports = scan_target(args.address, int(ports))

    if len(open_ports) > 0:
        for port in open_ports:
            log_message(f"Port {ports} is open", syslog.LOG_INFO)
    else:
        log_message("All ports are closed", syslog.LOG_INFO)

    log_message(f"Scan finished", syslog.LOG_INFO)
    exit(0)


if __name__ == "__main__":
    main()
