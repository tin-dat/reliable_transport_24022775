import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16

DEBUG = False


def log(*args):
    if DEBUG:
        print(*args, file=sys.stderr)
        sys.stderr.flush()


def make_packet(pkt_type, seq_num, data=b""):
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(data))
    header.checksum = compute_checksum(header / data)
    return bytes(header / data)


def parse_packet(raw):
    if len(raw) < HEADER_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    if len(raw) < HEADER_SIZE + header.length:
        return None
    data = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    if received_checksum != compute_checksum(header / data):
        return None
    return header, data


def receiver(receiver_ip, receiver_port, window_size):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))
    out = sys.stdout.buffer

    connected = False
    peer = None
    expected = 1
    buffer = {}

    while True:
        raw, addr = s.recvfrom(2048)

        parsed = parse_packet(raw)
        if parsed is None:
            continue
        header, data = parsed

        if header.type == START:
            if not connected:
                connected = True
                peer = addr
                expected = 1
                buffer = {}
                s.sendto(make_packet(ACK, 1), addr)
                log("START, connected")
            elif addr == peer and expected == 1 and not buffer:
                s.sendto(make_packet(ACK, 1), addr)
            continue

        if not connected:
            continue

        if header.type == DATA:
            seq = header.seq_num
            if seq >= expected + window_size:
                log("drop (ngoài window)", seq)
                continue
            if seq >= expected and seq not in buffer:
                buffer[seq] = data

            while expected in buffer:
                out.write(buffer.pop(expected))
                expected += 1
            out.flush()
            s.sendto(make_packet(ACK, expected), addr)
            log("DATA", seq, "-> ACK", expected)

        elif header.type == END:
            if header.seq_num == expected:
                s.sendto(make_packet(ACK, expected + 1), addr)
                log("END, exit")
                break
            else:
                s.sendto(make_packet(ACK, expected), addr)

    out.flush()
    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
