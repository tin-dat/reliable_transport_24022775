import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

T_START, T_END, T_DATA, T_ACK = 0, 1, 2, 3
HDR_LEN = 16
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


class ReorderBuffer:
    def __init__(self, capacity, sink):
        self.capacity = capacity
        self.sink = sink
        self.head = 1
        self.held = {}

    def in_range(self, seq):
        return seq < self.head + self.capacity

    def store(self, seq, payload):
        if seq >= self.head:
            self.held.setdefault(seq, payload)
        while self.head in self.held:
            self.sink.write(self.held.pop(self.head))
            self.head += 1
        self.sink.flush()


class RtpReceiver:
    def __init__(self, ip, port, window):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.window = window
        self.buf = None
        self.peer = None

    def ack(self, addr, seq):
        self.sock.sendto(encode(T_ACK, seq), addr)

    def on_start(self, addr, seq, payload):
        if self.buf is None:
            self.buf = ReorderBuffer(self.window, sys.stdout.buffer)
            self.peer = addr
            self.ack(addr, 1)
            trace("session opened")
        elif addr == self.peer and self.buf.head == 1 and not self.buf.held:
            self.ack(addr, 1)
        return False

    def on_data(self, addr, seq, payload):
        if self.buf is None or not self.buf.in_range(seq):
            return False
        self.buf.store(seq, payload)
        self.ack(addr, seq)
        trace("got", seq, "head", self.buf.head)
        return False

    def on_end(self, addr, seq, payload):
        if self.buf is None or seq != self.buf.head:
            return False
        self.ack(addr, seq)
        return True

    def serve(self):
        handlers = {T_START: self.on_start, T_DATA: self.on_data, T_END: self.on_end}
        finished = False
        while not finished:
            datagram, addr = self.sock.recvfrom(2048)
            msg = decode(datagram)
            if msg is None:
                continue
            kind, seq, payload = msg
            handler = handlers.get(kind)
            finished = bool(handler and handler(addr, seq, payload))
        sys.stdout.buffer.flush()
        self.sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("receiver_ip", help="The IP address of the host that receiver is running on")
    parser.add_argument("receiver_port", type=int, help="The port number on which receiver is listening")
    parser.add_argument("window_size", type=int, help="Maximum number of outstanding packets")
    args = parser.parse_args()
    RtpReceiver(args.receiver_ip, args.receiver_port, args.window_size).serve()


if __name__ == "__main__":
    main()
