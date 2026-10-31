import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16
MAX_PKT = 1472
MAX_DATA = MAX_PKT - HEADER_SIZE
TIMEOUT = 0.5

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
    header = PacketHeader(raw[:HEADER_SIZE])
    data = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    ok = (received_checksum == compute_checksum(header / data))
    return header, data, ok


def split_message(message):
    return [message[i:i + MAX_DATA] for i in range(0, len(message), MAX_DATA)]


def wait_for_ack(s, deadline):
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        s.settimeout(remaining)
        try:
            raw, _ = s.recvfrom(2048)
        except socket.timeout:
            return None
        if len(raw) < HEADER_SIZE:
            continue
        header, _, ok = parse_packet(raw)
        if ok and header.type == ACK:
            return header


def sender(receiver_ip, receiver_port, window_size):
    message = sys.stdin.buffer.read()
    chunks = split_message(message)
    dest = (receiver_ip, receiver_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    start_pkt = make_packet(START, 0)
    while True:
        s.sendto(start_pkt, dest)
        ack = wait_for_ack(s, time.time() + TIMEOUT)
        if ack is not None and ack.seq_num == 1:
            break
    log("START acked")

    total = len(chunks)
    end_seq = total + 1
    packets = {i + 1: make_packet(DATA, i + 1, chunks[i]) for i in range(total)}

    base = 1
    next_seq = 1
    deadline = time.time() + TIMEOUT

    while base < end_seq:
        while next_seq < base + window_size and next_seq < end_seq:
            s.sendto(packets[next_seq], dest)
            log("send", next_seq)
            next_seq += 1

        ack = wait_for_ack(s, deadline)

        if ack is None:
            log("timeout, resend", base, "->", next_seq - 1)
            for seq in range(base, next_seq):
                s.sendto(packets[seq], dest)
            deadline = time.time() + TIMEOUT
        elif base < ack.seq_num <= next_seq:
            base = ack.seq_num
            deadline = time.time() + TIMEOUT
            log("ack", ack.seq_num, "base ->", base)

    end_pkt = make_packet(END, end_seq)
    s.sendto(end_pkt, dest)
    deadline = time.time() + TIMEOUT
    while True:
        ack = wait_for_ack(s, deadline)
        if ack is None:
            log("END timer expired")
            break
        if ack.seq_num == end_seq + 1:
            log("END acked")
            break

    s.close()


def positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("window_size phải là số nguyên dương")
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=positive_int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
