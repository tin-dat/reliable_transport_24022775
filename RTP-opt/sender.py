import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

T_START, T_END, T_DATA, T_ACK = 0, 1, 2, 3
HDR_LEN = 16
PAYLOAD_MAX = 1472 - HDR_LEN
RTO = 0.5
DEBUG = False


def trace(*parts):
    if DEBUG:
        sys.stderr.write(" ".join(str(p) for p in parts) + "\n")
        sys.stderr.flush()


def encode(kind, seq, payload=b""):
    hdr = PacketHeader(type=kind, seq_num=seq, length=len(payload), checksum=0)
    hdr.checksum = compute_checksum(hdr / payload)
    return bytes(hdr / payload)


def decode(datagram):
    if len(datagram) < HDR_LEN:
        return None
    hdr = PacketHeader(datagram[:HDR_LEN])
    payload = datagram[HDR_LEN:HDR_LEN + hdr.length]
    if len(payload) != hdr.length:
        return None
    claimed = hdr.checksum
    hdr.checksum = 0
    if compute_checksum(hdr / payload) != claimed:
        return None
    return hdr.type, hdr.seq_num, payload


class Timer:
    def __init__(self, span):
        self.span = span
        self.expiry = 0.0

    def restart(self):
        self.expiry = time.monotonic() + self.span

    def remaining(self):
        return max(0.0, self.expiry - time.monotonic())


class SendWindow:
    def __init__(self, size, last):
        self.size = size
        self.last = last
        self.lo = 1
        self.hi = 1
        self.acked = set()

    def fresh(self):
        limit = min(self.lo + self.size, self.last + 1)
        batch = list(range(self.hi, limit))
        self.hi = max(self.hi, limit)
        return batch

    def missing(self):
        return [q for q in range(self.lo, self.hi) if q not in self.acked]

    def record(self, seq):
        if not (self.lo <= seq < self.hi):
            return False
        self.acked.add(seq)
        before = self.lo
        while self.lo in self.acked:
            self.acked.remove(self.lo)
            self.lo += 1
        return self.lo != before

    def complete(self):
        return self.lo > self.last


class RtpSender:
    def __init__(self, ip, port, window_size):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dest = (ip, port)
        self.window_size = window_size
        self.timer = Timer(RTO)

    def emit(self, datagram):
        self.sock.sendto(datagram, self.dest)

    def listen_ack(self):
        while True:
            left = self.timer.remaining()
            if left <= 0:
                return None
            self.sock.settimeout(left)
            try:
                datagram, _ = self.sock.recvfrom(2048)
            except socket.timeout:
                return None
            msg = decode(datagram)
            if msg is not None and msg[0] == T_ACK:
                return msg[1]

    def handshake(self):
        hello = encode(T_START, 0)
        while True:
            self.emit(hello)
            self.timer.restart()
            if self.listen_ack() == 1:
                break
        self.timer.span = 0.1
        self.timer.restart()
        while self.listen_ack() is not None:
            pass
        self.timer.span = RTO

    def transfer(self, chunks):
        frames = {n: encode(T_DATA, n, c) for n, c in enumerate(chunks, start=1)}
        win = SendWindow(self.window_size, len(chunks))
        self.timer.restart()
        while not win.complete():
            for seq in win.fresh():
                self.emit(frames[seq])
            acked = self.listen_ack()
            if acked is None:
                for seq in win.missing():
                    self.emit(frames[seq])
                trace("retransmit", win.missing())
                self.timer.restart()
            elif win.record(acked):
                self.timer.restart()
        return len(chunks) + 1

    def close(self, end_seq):
        self.emit(encode(T_END, end_seq))
        self.timer.restart()
        while self.listen_ack() not in (None, end_seq):
            pass
        self.sock.close()


def run_sender(ip, port, window_size):
    message = sys.stdin.buffer.read()
    chunks = [message[i:i + PAYLOAD_MAX] for i in range(0, len(message), PAYLOAD_MAX)]
    tx = RtpSender(ip, port, window_size)
    tx.handshake()
    end_seq = tx.transfer(chunks)
    tx.close(end_seq)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()
    run_sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
