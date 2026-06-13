"""
UDP Socket Server - 模拟TCP连接建立与可靠传输
运行方式: python3 udpserver.py <port>
示例: python3 udpserver.py 12345
"""

import socket
import struct
import random
import time
import sys
import fcntl

LOG_FILE = "server_run_log.txt"   # 日志文件
DROP_RATE = 0.2            # 模拟丢包率
XOR_KEY = 0x5A3C

# 连接建立报文 18字节
CONN_HEADER_FMT = '!BBHIIHHH'
CONN_HEADER_LEN = struct.calcsize(CONN_HEADER_FMT)

# 数据报文 16字节
DATA_HEADER_FMT = '!BBHIIHH'
DATA_HEADER_LEN = struct.calcsize(DATA_HEADER_FMT)

# 报文类型
TYPE_SYN = 0x01
TYPE_SYN_ACK = 0x02
TYPE_ACK = 0x03
TYPE_DATA = 0x04
TYPE_FIN = 0x05

# 标志位
FLAG_NONE = 0x00
FLAG_ACK = 0x01
FLAG_RETRANS = 0x02


# 用来写日志
def write_log(msg):
    """日志"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_line = f"[{timestamp}] [server] {msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        # 文件排他锁，多进程防并发乱行
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(log_line)
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    print(log_line.strip())


def write_log_no_time(msg):
    """日志"""
    log_line = f"{msg}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        # 文件排他锁，多进程防并发乱行
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(log_line)
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    print(log_line.strip())


def calculate_crc(data: bytes) -> int:
    """简单CRC校验"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
    return crc & 0xFFFF


def verify_student_id(student_id: int) -> bool:
    """校验StudentID"""
    original = student_id ^ XOR_KEY
    return 0 <= original <= 9999


# 报文组装/解析
def create_conn_header(pkt_type, flags, student_id, seq_num, ack_num, window, data_len, crc):
    return struct.pack(CONN_HEADER_FMT, pkt_type, flags, student_id, seq_num, ack_num, window, data_len, crc)


def parse_conn_header(data):
    if len(data) < CONN_HEADER_LEN:
        return None
    try:
        return struct.unpack(CONN_HEADER_FMT, data[:CONN_HEADER_LEN])
    except struct.error:
        return None


def create_data_header(pkt_type, flags, seq_num, ack_num, data_len, crc, reserved=0):
    return struct.pack(DATA_HEADER_FMT, pkt_type, flags, seq_num & 0xFFFF, ack_num, data_len, crc, reserved)


def parse_data_header(data):
    if len(data) < DATA_HEADER_LEN:
        return None
    try:
        return struct.unpack(DATA_HEADER_FMT, data[:DATA_HEADER_LEN])
    except struct.error:
        return None


def make_ack(ack_num):
    """快速生成ACK报文"""
    return create_data_header(TYPE_ACK, FLAG_ACK, 0, ack_num, 0, 0)


def main():
    if len(sys.argv) < 2:
        print("用法: python server.py <port>")
        print("示例: python server.py 12345")
        sys.exit(1)

    server_port = int(sys.argv[1])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    sock.bind(('', server_port))

    open(LOG_FILE, "w", encoding="utf-8").close()

    # 写入服务端日志
    write_log_no_time("===== Server Log Start =====")
    write_log(f"Server listening on port {server_port}, CONN_HEADER_LEN={CONN_HEADER_LEN}, DATA_HEADER_LEN={DATA_HEADER_LEN}")

    print(f"[Server] UDP服务器启动，监听端口 {server_port}")
    print(f"[Server] 模拟丢包率: {DROP_RATE * 100:.0f}%")
    print("[Server] 按 Ctrl+C 停止服务器")

    client_addr = None
    connected = False
    expected_seq = 0
    running = True

    try:
        while running:
            try:
                data, addr = sock.recvfrom(2048)
                if len(data) < 2:
                    continue
                pkt_type = data[0]

                # 处理SYN连接请求
                if pkt_type == TYPE_SYN:
                    header = parse_conn_header(data)
                    if not header:
                        continue
                    _, flags, student_id, seq_num, ack_num, window, data_len, crc = header
                    write_log(f"RECV SYN from {addr}, StudentID=0x{student_id:04X}")

                    if not verify_student_id(student_id):
                        write_log("StudentID验证失败，拒绝连接")
                        resp = create_conn_header(TYPE_SYN_ACK, FLAG_NONE, 0, 0, 0, 0, 0, 0)
                        sock.sendto(resp, addr)
                        continue

                    # 回复SYN-ACK
                    resp = create_conn_header(TYPE_SYN_ACK, FLAG_ACK, 0, 0, seq_num + 1, 400, 0, 0)
                    sock.sendto(resp, addr)
                    client_addr = addr
                    connected = True
                    expected_seq = 0
                    write_log(f"SEND SYN-ACK to {addr}, connection established")
                    continue

                # 处理FIN断开连接
                if pkt_type == TYPE_FIN:
                    write_log(f"RECV FIN from {addr}")
                    resp = create_data_header(TYPE_FIN, FLAG_ACK, 0, 0, 0, 0)
                    sock.sendto(resp, addr)
                    connected = False
                    client_addr = None
                    write_log("Connection released, wait new client")
                    continue

                # 处理DATA数据报文
                if pkt_type == TYPE_DATA:
                    if not connected or addr != client_addr:
                        continue
                    header = parse_data_header(data)
                    if not header:
                        continue
                    _, flags, seq_num, ack_num, data_len, crc, reserved = header
                    payload = data[DATA_HEADER_LEN:]

                    # 模拟随机丢包
                    if random.random() < DROP_RATE:
                        write_log(f"DROP seq={seq_num} (simulated packet loss)")
                        continue

                    calc_crc = calculate_crc(payload)
                    retrans = "(retrans)" if flags & FLAG_RETRANS else ""
                    print(f"[Server] RECV DATA seq={seq_num}, len={data_len} {retrans}")
                    write_log(f"RECV DATA seq={seq_num}, len={data_len}")

                    # GBN协议
                    if seq_num == expected_seq:
                        expected_seq += 1
                        resp = make_ack(expected_seq)
                        sock.sendto(resp, addr)
                        write_log(f"SEND ACK ack={expected_seq}")
                    elif seq_num < expected_seq:
                        # 重复包，回送最新ACK
                        resp = make_ack(expected_seq)
                        sock.sendto(resp, addr)
                        write_log(f"SEND ACK ack={expected_seq} (duplicate)")
                    else:
                        # 乱序包直接丢弃
                        write_log(f"DROP seq={seq_num} (out of order)")

            except socket.timeout:
                continue
            except OSError:
                break

    except KeyboardInterrupt:
        print("\n[Server] 收到 Ctrl+C，正在关闭...")
    except Exception as e:
        print(f"\n[Server] 运行错误: {e}")
        write_log(f"Server Error: {e}")
    finally:
        running = False
        sock.close()
        write_log_no_time("===== Server Log End =====")
        print("[Server] 服务器已关闭")


if __name__ == "__main__":
    main()
