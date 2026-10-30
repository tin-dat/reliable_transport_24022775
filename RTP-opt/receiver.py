import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

# Loại gói
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16

DEBUG = False


def log(*args):
    """In debug ra stderr. TUYỆT ĐỐI không in ra stdout vì stdout là file output."""
    if DEBUG:
        print(*args, file=sys.stderr)
        sys.stderr.flush()


def make_packet(pkt_type, seq_num, data=b""):
    """Tạo gói hoàn chỉnh (header + data) dạng bytes, đã có checksum."""
    header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(data))
    header.checksum = compute_checksum(header / data)
    return bytes(header / data)


def parse_packet(raw):
    """Trả về (header, data) nếu gói hợp lệ, ngược lại trả về None."""
    if len(raw) < HEADER_SIZE:
        return None
    header = PacketHeader(raw[:HEADER_SIZE])
    if len(raw) < HEADER_SIZE + header.length:
        return None
    data = raw[HEADER_SIZE:HEADER_SIZE + header.length]
    received_checksum = header.checksum
    header.checksum = 0
    if received_checksum != compute_checksum(header / data):
        return None  # hỏng checksum -> bỏ gói, không ACK
    return header, data


def receiver(receiver_ip, receiver_port, window_size):
    """Nhận message, ghi ra stdout, gửi ACK RIÊNG cho từng gói (selective ACK)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))
    out = sys.stdout.buffer

    connected = False
    expected = 1      # N: seq_num nhỏ nhất chưa nhận đủ (đầu window)
    buffer = {}       # seq_num -> data của các gói đến sai thứ tự

    while True:
        raw, addr = s.recvfrom(2048)

        parsed = parse_packet(raw)
        if parsed is None:
            continue
        header, data = parsed

        # ---------- START ----------
        if header.type == START:
            if not connected:          # đang có kết nối thì bỏ qua START
                connected = True
                expected = 1
                buffer = {}
                s.sendto(make_packet(ACK, 1), addr)
                log("START, connected")
            continue

        if not connected:
            continue

        # ---------- DATA ----------
        if header.type == DATA:
            seq = header.seq_num
            if seq >= expected + window_size:
                log("drop (ngoài window)", seq)
                continue               # bỏ gói, không ACK
            if seq >= expected and seq not in buffer:
                buffer[seq] = data     # lưu gói (kể cả sai thứ tự)
            # Ghi ra các gói liên tiếp bắt đầu từ `expected`
            while expected in buffer:
                out.write(buffer.pop(expected))
                expected += 1
            # ACK RIÊNG: seq_num đúng bằng seq_num của gói vừa nhận
            # (kể cả gói cũ seq < expected, vì ACK trước đó có thể đã bị mất)
            s.sendto(make_packet(ACK, seq), addr)
            log("DATA", seq, "-> ACK", seq, "| expected =", expected)

        # ---------- END ----------
        elif header.type == END:
            if header.seq_num == expected:
                s.sendto(make_packet(ACK, header.seq_num), addr)
                log("END, exit")
                break
            # END chỉ được gửi sau khi mọi DATA đã được ACK nên bình thường
            # luôn có seq_num == expected; nếu không thì bỏ qua.

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
