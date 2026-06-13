"""
UDP Socket Client - 模拟TCP连接建立与GBN可靠传输
计算机网络实验2
运行方式: python client.py <serverIP> <serverPort> <学号后4位>
示例: python client.py 192.168.56.101 12345 1511
"""

import socket
import struct
import random
import time
import sys
import os
import threading
import pandas as pd
from datetime import datetime


# 日志文件名
LOG_FILE = "client_run_log.txt"
# 本地线程锁
LOG_LOCK = threading.Lock()


def write_log(msg: str):
    """日志写入"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    log_line = f"[{timestamp}] [client] {msg}\n"
    # 加锁
    with LOG_LOCK:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
            f.flush()
            f.seek(0, 2)
        time.sleep(0.001)
    print(log_line.strip())


def write_log_no_time(msg: str):
    """日志"""
    log_line = f"{msg}\n"
    with LOG_LOCK:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
            f.flush()
            f.seek(0, 2)
        time.sleep(0.001)
    print(log_line.strip())


# 连接建立报文首部 (18字节, 8个参数)
# Type(1) + Flags(1) + StudentID(2) + SeqNum(4) + AckNum(4) + Window(2) + DataLen(2) + CRC(2) = 18字节
CONN_HEADER_FMT = '!BBHIIHHH'
CONN_HEADER_LEN = struct.calcsize(CONN_HEADER_FMT)

# 数据传输报文首部 (16字节, 7个参数)
# Type(1) + Flags(1) + SeqNum(2) + AckNum(4) + DataLen(2) + CRC(2) + Reserved(2) = 16字节
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
FLAG_RETRANS = 0x02  # 重传标记

# XOR密钥
XOR_KEY = 0x5A3C

# 配置参数
WINDOW_SIZE = 400  # 发送窗口大小 400字节
MIN_PKT_SIZE = 40  # 最小数据包大小
MAX_PKT_SIZE = 80  # 最大数据包大小
BASE_TIMEOUT = 0.3  # 基础超时时间300ms
TOTAL_PACKETS = 30  # 总共发送30个数据包


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


def create_conn_header(pkt_type, flags, student_id, seq_num, ack_num, window, data_len, crc):
    """创建连接建立报文首部 - 8个参数"""
    return struct.pack(CONN_HEADER_FMT, pkt_type, flags, student_id, seq_num, ack_num, window, data_len, crc)


def parse_conn_header(data):
    """解析连接建立报文首部"""
    if len(data) < CONN_HEADER_LEN:
        return None
    try:
        return struct.unpack(CONN_HEADER_FMT, data[:CONN_HEADER_LEN])
    except struct.error as e:
        print(f"[Client Debug] 解析连接首部失败: {e}, 数据长度={len(data)}, 期望长度={CONN_HEADER_LEN}")
        return None


def create_data_header(pkt_type, flags, seq_num, ack_num, data_len, crc, reserved=0):
    """创建数据传输报文首部 - 7个参数"""
    return struct.pack(DATA_HEADER_FMT, pkt_type, flags, seq_num & 0xFFFF, ack_num, data_len, crc, reserved)


def parse_data_header(data):
    """解析数据传输报文首部"""
    if len(data) < DATA_HEADER_LEN:
        return None
    try:
        return struct.unpack(DATA_HEADER_FMT, data[:DATA_HEADER_LEN])
    except struct.error as e:
        print(f"[Client Debug] 解析数据首部失败: {e}, 数据长度={len(data)}, 期望长度={DATA_HEADER_LEN}")
        return None


def get_current_time_str():
    """获取当前时间字符串"""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def compute_student_id(last_4_digits: str) -> int:
    """
    计算StudentID: 学号后4位 XOR 0x5A3C
    示例: 1511 XOR 0x5A3C = 0x5FDB
    """
    num = int(last_4_digits)
    return num ^ XOR_KEY


class GBNClient:
    def __init__(self, server_ip, server_port, student_id_last4):
        self.server_ip = server_ip
        self.server_port = server_port
        self.server_addr = (server_ip, server_port)
        self.student_id = compute_student_id(student_id_last4)
        self.student_id_last4 = student_id_last4

        # 创建UDP socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(1.0)

        self.connected = False
        self.base = 0
        self.next_seq = 0
        self.window = []
        self.rtt_list = []
        self.timeout_interval = BASE_TIMEOUT

        self.total_sent = 0
        self.retransmit_count = 0
        self.ack_received = threading.Event()
        self.latest_ack = 0

        self.lock = threading.Lock()
        self.running = True

        write_log_no_time("==================== Client Log Start ====================")
        write_log(
            f"Server: {server_ip}:{server_port}, StudentID: 0x{self.student_id:04X} (学号后4位: {student_id_last4})")
        write_log(f"CONN_HEADER_LEN={CONN_HEADER_LEN}, DATA_HEADER_LEN={DATA_HEADER_LEN}")

        # 启动接收线程
        self.recv_thread = threading.Thread(target=self._receive_loop)
        self.recv_thread.daemon = True
        self.recv_thread.start()

    def _receive_loop(self):
        """后台接收线程"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
                recv_time = time.time()

                if len(data) < 2:
                    continue

                pkt_type = data[0]

                with self.lock:
                    if pkt_type == TYPE_SYN_ACK:
                        header = parse_conn_header(data)
                        if header:
                            _, flags, _, _, ack_num, window, _, _ = header
                            if flags & FLAG_ACK:
                                self.connected = True
                                print(f"[Client] 收到SYN-ACK，连接建立成功")
                                write_log("RECV SYN-ACK, connection established")
                    elif pkt_type == TYPE_ACK:
                        header = parse_data_header(data)
                        if header:
                            _, flags, _, ack_num, _, _, _ = header
                            if flags & FLAG_ACK:
                                self.latest_ack = ack_num
                                self.ack_received.set()

                                for i, (seq, pkt_data, sent_time, retry, start_byte, end_byte) in enumerate(
                                        self.window):
                                    if seq < ack_num and sent_time > 0:
                                        rtt = (recv_time - sent_time) * 1000
                                        if rtt > 0 and rtt < 10000:
                                            self.rtt_list.append(rtt)
                                            if len(self.rtt_list) >= 3:
                                                recent_rtts = self.rtt_list[-5:]
                                                avg_rtt = sum(recent_rtts) / len(recent_rtts)
                                                new_timeout = max(avg_rtt * 5 / 1000, 0.05)
                                                if abs(new_timeout - self.timeout_interval) > 0.01:
                                                    self.timeout_interval = new_timeout
                                                    print(
                                                        f"[Client] 动态调整超时时间为 {self.timeout_interval * 1000:.1f}ms")

                                print(f"[Client] 收到ACK ack={ack_num}")
                                write_log(f"RECV ACK ack={ack_num}")
                    elif pkt_type == TYPE_FIN:
                        header = parse_data_header(data)
                        if header:
                            _, flags, _, _, _, _, _ = header
                            if flags & FLAG_ACK:
                                print(f"[Client] 收到FIN-ACK")
                                write_log("RECV FIN-ACK")
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"[Client] 接收线程错误: {e}")

    def connect(self):
        """建立连接"""
        print(f"[Client] 开始连接服务器 {self.server_addr}")
        print(f"[Client] 学号后4位: {self.student_id_last4}")
        print(f"[Client] StudentID = 0x{self.student_id:04X}")
        print(f"[Client] 连接首部长度: {CONN_HEADER_LEN} 字节, 数据首部长度: {DATA_HEADER_LEN} 字节")

        syn_pkt = create_conn_header(TYPE_SYN, FLAG_NONE, self.student_id, 0, 0, WINDOW_SIZE, 0, 0)
        print(f"[Client] SYN报文长度: {len(syn_pkt)} 字节")

        for attempt in range(5):
            self.sock.sendto(syn_pkt, self.server_addr)
            print(f"[Client] 发送SYN (尝试 {attempt + 1}/5)")
            write_log(f"SEND SYN (attempt {attempt + 1})")

            start_time = time.time()
            while time.time() - start_time < 2.0:
                if self.connected:
                    return True
                time.sleep(0.05)

        print("[Client] 连接失败")
        return False

    def send_data(self):
        """发送数据 - GBN协议"""
        if not self.connected:
            print("[Client] 未连接")
            return

        all_data = []
        byte_offset = 0
        for i in range(TOTAL_PACKETS):
            pkt_size = random.randint(MIN_PKT_SIZE, MAX_PKT_SIZE)
            data = bytes([i % 256] * pkt_size)
            all_data.append((i, byte_offset, byte_offset + pkt_size - 1, data, pkt_size))
            byte_offset += pkt_size

        print(f"[Client] 开始发送 {TOTAL_PACKETS} 个数据包，总数据量 {byte_offset} 字节")

        write_log(f"Start sending {TOTAL_PACKETS} packets")

        self.base = 0
        self.next_seq = 0

        while self.base < TOTAL_PACKETS:
            with self.lock:
                window_bytes = 0
                window_packets = []
                for seq, start_byte, end_byte, data, pkt_size in all_data[self.base:]:
                    if window_bytes + pkt_size <= WINDOW_SIZE and len(window_packets) < 10:
                        window_packets.append((seq, start_byte, end_byte, data, pkt_size))
                        window_bytes += pkt_size
                    else:
                        break

                for seq, start_byte, end_byte, data, pkt_size in window_packets:
                    existing = False
                    for w_seq, w_data, w_sent, w_retry, w_start, w_end in self.window:
                        if w_seq == seq:
                            existing = True
                            break

                    if not existing:
                        crc = calculate_crc(data)
                        header = create_data_header(TYPE_DATA, FLAG_NONE, seq, 0, pkt_size, crc)
                        pkt = header + data

                        self.sock.sendto(pkt, self.server_addr)
                        self.total_sent += 1
                        send_time = time.time()
                        self.window.append((seq, data, send_time, 0, start_byte, end_byte))

                        print(f"第{seq + 1}个（第{start_byte}~{end_byte}字节）client端已经发送")
                        write_log(f"SEND DATA seq={seq}, bytes={start_byte}~{end_byte}")

                        time.sleep(0.01)

            acked = self.ack_received.wait(timeout=self.timeout_interval)

            with self.lock:
                if acked:
                    self.ack_received.clear()
                    ack_num = self.latest_ack

                    new_window = []
                    for seq, data, sent_time, retry, start_byte, end_byte in self.window:
                        if seq >= ack_num:
                            new_window.append((seq, data, sent_time, retry, start_byte, end_byte))
                        else:
                            if sent_time > 0:
                                rtt = (time.time() - sent_time) * 1000
                                if rtt > 0 and rtt < 10000:
                                    self.rtt_list.append(rtt)
                                    print(
                                        f"第{seq + 1}个（第{start_byte}~{end_byte}字节）server端已经收到，RTT是{rtt:.1f}ms")
                                    write_log(f"ACKED seq={seq}, RTT={rtt:.1f}ms")

                    self.window = new_window
                    self.base = ack_num

                    if self.base >= TOTAL_PACKETS:
                        break
                else:
                    print(f"[Client] 超时! 重传窗口 (base={self.base})")
                    write_log(f"TIMEOUT, retransmit base={self.base}")

                    for i, (seq, data, sent_time, retry, start_byte, end_byte) in enumerate(self.window):
                        crc = calculate_crc(data)
                        header = create_data_header(TYPE_DATA, FLAG_RETRANS, seq, 0, len(data), crc)
                        pkt = header + data

                        self.sock.sendto(pkt, self.server_addr)
                        self.total_sent += 1
                        self.retransmit_count += 1
                        self.window[i] = (seq, data, time.time(), retry + 1, start_byte, end_byte)

                        print(f"重传第{seq + 1}个（第{start_byte}~{end_byte}字节）数据包")
                        write_log(f"RETRANS seq={seq}, retry={retry + 1}")

                        time.sleep(0.01)

        print(f"[Client] 所有数据包发送完成")

    def disconnect(self):
        """释放连接"""
        print(f"[Client] 发送FIN")
        fin_pkt = create_data_header(TYPE_FIN, FLAG_NONE, 0, 0, 0, 0)
        self.sock.sendto(fin_pkt, self.server_addr)
        write_log("SEND FIN")

        time.sleep(0.5)

    def print_summary(self):
        """打印汇总"""
        print("\n" + "=" * 60)
        print("【汇总信息】")
        print("=" * 60)

        if self.total_sent > 0:
            drop_rate = (1 - TOTAL_PACKETS / self.total_sent) * 100
        else:
            drop_rate = 0

        print(f"丢包率：{drop_rate:.1f}% (按 {TOTAL_PACKETS} ÷ {self.total_sent} 计算)")
        print(f"总发送包数: {self.total_sent}")
        print(f"重传次数: {self.retransmit_count}")

        if self.rtt_list:
            df = pd.DataFrame(self.rtt_list, columns=['RTT'])
            max_rtt = df['RTT'].max()
            min_rtt = df['RTT'].min()
            avg_rtt = df['RTT'].mean()
            std_rtt = df['RTT'].std()

            print(f"\nRTT统计 (pandas):")
            print(f"  样本数: {len(self.rtt_list)}")
            print(f"  最大RTT: {max_rtt:.2f} ms")
            print(f"  最小RTT: {min_rtt:.2f} ms")
            print(f"  平均RTT: {avg_rtt:.2f} ms")
            print(f"  标准差: {std_rtt:.2f} ms")
        else:
            print("\n无RTT数据")

        print("=" * 60)

        write_log_no_time("")
        write_log_no_time("===== Summary =====")
        write_log_no_time(f"丢包率：{drop_rate:.1f}% (按 {TOTAL_PACKETS} ÷ {self.total_sent} 计算)")
        write_log_no_time(f"总发送包数: {self.total_sent}")
        write_log_no_time(f"重传次数: {self.retransmit_count}")
        if self.rtt_list:
            write_log_no_time(f"\nRTT统计 (pandas):")
            write_log_no_time(f"  \t样本数: {len(self.rtt_list)}")
            write_log_no_time(f"  \t最大RTT: {max_rtt:.2f} ms")
            write_log_no_time(f"  \t最小RTT: {min_rtt:.2f} ms")
            write_log_no_time(f"  \t平均RTT: {avg_rtt:.2f} ms")
            write_log_no_time(f"  \t标准差: {std_rtt:.2f} ms")
        write_log_no_time(f"===== Client Log End at {get_current_time_str()} =====")

    def close(self):
        self.running = False
        self.recv_thread.join(timeout=2)
        self.sock.close()
        print("[Client] 客户端已关闭")


def main():
    if len(sys.argv) < 4:
        print("=" * 60)
        print("UDP Socket Client - 计算机网络")
        print("=" * 60)
        print("用法: python client.py <serverIP> <serverPort> <学号后4位>")
        print("示例: python client.py 192.168.56.101 12345 1511")
        print("=" * 60)
        sys.exit(1)

    server_ip = sys.argv[1]
    server_port = int(sys.argv[2])
    student_id_last4 = sys.argv[3]

    if not student_id_last4.isdigit() or len(student_id_last4) != 4:
        print("错误: 学号后4位必须是4位数字")
        sys.exit(1)

    # open(LOG_FILE, "w", encoding="utf-8").close()
    client = GBNClient(server_ip, server_port, student_id_last4)

    try:
        if client.connect():
            client.send_data()
            client.disconnect()
            client.print_summary()
        else:
            print("[Client] 连接失败")
    except KeyboardInterrupt:
        print("\n[Client] 用户中断")
    except Exception as e:
        print(f"[Client] 运行时错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    main()
