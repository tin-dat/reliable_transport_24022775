import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Loại gói
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16
MAX_PKT = 1472
MAX_DATA = MAX_PKT - HEADER_SIZE  # 1456 byte dữ liệu mỗi gói
TIMEOUT = 0.5                     # 500 ms

DEBUG = False


def log(*args):
    if DEBUG:
        print(*args, file=sys.stderr)
        sys.stderr.flush()


def make_packet(pkt_type, seq_num, data=b""):
    """Tạo gói hoàn chỉnh (header + data) dạng bytes, đã có checksum."""
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(data))
    header.checksum = compute_checksum(header / data)
    return bytes(header / data)


def parse_packet(raw):
    """Tách gói nhận được. Trả về (header, data, checksum_ok)."""
    header = PacketHeader(raw[:HEADER_SIZE])
    data = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    ok = (received_checksum == compute_checksum(header / data))
    return header, data, ok


def split_message(message):
    """Cắt message (bytes) thành các chunk tối đa MAX_DATA byte."""
    return [message[i:i + MAX_DATA] for i in range(0, len(message), MAX_DATA)]


def wait_for_ack(s, deadline):
    """Chờ đến `deadline`. Trả về header của ACK hợp lệ đầu tiên, hoặc None."""
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
    """Đọc message từ stdin, gửi theo RTP với selective ACK."""
    message = sys.stdin.buffer.read()
    chunks = split_message(message)
    dest = (receiver_ip, receiver_port)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # ---------- 1. Bắt tay: START (seq 0), chờ ACK seq 1 ----------
    start_pkt = make_packet(START, 0)
    while True:
        s.sendto(start_pkt, dest)
        ack = wait_for_ack(s, time.time() + TIMEOUT)
        if ack is not None and ack.seq_num == 1:
            break

    # ---------- 2. Gửi DATA: sliding window + selective ACK ----------
    total = len(chunks)
    end_seq = total + 1
    packets = {i + 1: make_packet(DATA, i + 1, chunks[i]) for i in range(total)}

    base = 1          # seq nhỏ nhất chưa được ACK (đầu window)
    next_seq = 1      # seq tiếp theo sẽ gửi
    acked = set()     # các seq đã được ACK riêng (kể cả ngoài base)
    deadline = time.time() + TIMEOUT

    while base < end_seq:
        # Gửi thêm các gói trong cửa sổ [base, base + window_size)
        while next_seq < base + window_size and next_seq < end_seq:
            s.sendto(packets[next_seq], dest)
            log("send", next_seq)
            next_seq += 1

        ack = wait_for_ack(s, deadline)

        if ack is None:
            # Hết 500 ms: chỉ gửi lại các gói CHƯA được ACK trong window
            missing = [q for q in range(base, next_seq) if q not in acked]
            log("timeout, resend", missing)
            for q in missing:
                s.sendto(packets[q], dest)
            deadline = time.time() + TIMEOUT
        else:
            seq = ack.seq_num
            if base <= seq < next_seq:         # ACK nằm trong window
                acked.add(seq)
                if seq == base:
                    # Trượt window qua mọi gói liên tiếp đã được ACK
                    while base in acked:
                        acked.discard(base)
                        base += 1
                    deadline = time.time() + TIMEOUT   # window tiến -> reset timer
                    log("window ->", base)
            # ACK ngoài window / trùng lặp: bỏ qua

    # ---------- 3. Kết thúc: gửi END, chờ ACK hoặc 500 ms ----------
    end_pkt = make_packet(END, end_seq)
    s.sendto(end_pkt, dest)
    deadline = time.time() + TIMEOUT
    while True:
        ack = wait_for_ack(s, deadline)
        if ack is None:
            break                              # hết 500 ms
        if ack.seq_num == end_seq:             # ACK của END
            break

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

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
