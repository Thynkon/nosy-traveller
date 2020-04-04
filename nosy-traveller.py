#! /usr/bin/env python3

import argparse
import socket
import syslog


def log_message(message, facility):
    print(message)
    syslog.syslog(facility, message)


def scan_target(address, ports):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((address, ports))
        except ConnectionError:
            log_message(f"Port {ports} is closed", syslog.LOG_INFO)
        else:
            log_message(f"Port {ports} is open", syslog.LOG_INFO)

        log_message("Scan finished", syslog.LOG_INFO)


def main():
    parser = argparse.ArgumentParser(description="A simple port scanner")
    parser.add_argument("-a", "--address",
                        help="target's ip address", required=True)
    parser.add_argument("-p", "--ports",
                        help="target's port")
    args = parser.parse_args()

    address = args.address
    ports = args.ports

    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)

    log_message(f"Scanning {address}", syslog.LOG_INFO)
    scan_target(args.address, int(ports))

    exit(0)


if __name__ == "__main__":
    main()
