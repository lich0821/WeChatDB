#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import segno
import struct
import binascii
from pymem import Pymem
from win32api import GetFileVersionInfo, HIWORD, LOWORD


def error():
    print("请按提示排查，如仍有问题可扫描二维码联系作者")
    qrcode = segno.make("http://weixin.qq.com/r/OzopMZrEuMfHrd5S928p")
    qrcode.show()
    exit(-1)


def getVersionBase(pm):
    WeChatWindll_base = 0
    WeChatWindll_path = ""
    for m in list(pm.list_modules()):
        path = m.filename
        if path.endswith("WeChatWin.dll"):
            WeChatWindll_base = m.lpBaseOfDll
            WeChatWindll_path = path
            break

    if not WeChatWindll_path:
        print("获取版本失败，请确认本系统是否成功安装了微信！")
        error()

    version = GetFileVersionInfo(WeChatWindll_path, "\\")

    msv = version['FileVersionMS']
    lsv = version['FileVersionLS']
    version = f"{str(HIWORD(msv))}.{str(LOWORD(msv))}.{str(HIWORD(lsv))}.{str(LOWORD(lsv))}"

    return version, WeChatWindll_base


def getAesKey(pm, base, offset):
    try:
        result = pm.read_bytes(base + offset, 4)    # 读取 AES Key 的地址
        addr = struct.unpack("<I", result)[0]       # 地址为小端 4 字节整型
        aesKey = pm.read_bytes(addr, 0x20)          # 读取 AES Key
        result = binascii.b2a_hex(aesKey)           # 解码
    except Exception as e:
        print(f"{e}")
        print(f"请确认微信已经登录！")
        error()

    return result.decode()


AESKEY_OFFSETS = {
    "3.3.0.115": 0x1DDF914,
    "3.3.5.34": 0x1D2FB34,
    "3.6.0.18": 0x222EFE4,
    "3.7.0.29": 0x2363524,
    "3.7.0.30": 0x2366524,
    "3.7.5.23": 0x242413C,
    "3.8.1.26": 0x2C429FC,
}

if __name__ == "__main__":
    try:
        pm = Pymem("WeChat.exe")
    except Exception as e:
        print(f"{e}，请确认微信程序已经打开并登录！")
        error()

    version, base = getVersionBase(pm)
    print(f"微信版本：{version}\n微信基址：{hex(base)}")

    offset = AESKEY_OFFSETS.get(version, None)
    if not offset:
        print(f"暂不支持版本 {version}，请联系作者。")
        error()

    print(f"偏移地址：{hex(offset)}")

    aesKey = getAesKey(pm, base, offset)
    print(f"数据库密钥：{aesKey}")
