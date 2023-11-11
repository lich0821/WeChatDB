#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import binascii
import os
import struct

import segno
from pymem import Pymem, pattern, process
from win32api import HIWORD, LOWORD, GetFileVersionInfo


def error():
    print("请按提示排查，如仍有问题可扫描二维码联系作者")
    qrcode = segno.make("http://weixin.qq.com/r/OzopMZrEuMfHrd5S928p")
    qrcode.show()
    exit(-1)


def getDllArch(dll_file):
    """Get DLL arch type
    Adapted from: http://stackoverflow.com/a/495305/1338797
    """
    with open(dll_file, "rb") as f:
        doshdr = f.read(64)
        magic, padding, offset = struct.unpack("2s58si", doshdr)

        if magic != b"MZ":
            return None
        f.seek(offset, os.SEEK_SET)
        pehdr = f.read(6)

        # careful! H == unsigned short, x64 is negative with signed
        magic, padding, machine = struct.unpack("2s2sH", pehdr)

        if magic != b"PE":
            return None
        if machine == 0x014c:
            return "i386"
        if machine == 0x0200:
            return "IA64"
        if machine == 0x8664:
            return "x64"

        return "unknown"


def is64Bit(pm):
    exe_arch = getDllArch(list(pm.list_modules())[0].filename)
    if exe_arch == "x64":
        return True
    else:
        return False


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


def getOffsetByWxNum(pm, id):
    """Get Key offset by WeChat Number
        Tested with
            3.9.5.91 (64bit)
            3.9.7.29 (64bit)
            3.9.8.15 (64bit)
            3.9.5.80 (32bit)
            3.9.2.23 (32bit)
    """
    bytes_pattern = bytearray()
    bytes_pattern.extend(map(ord, id))
    id_pattern = bytes(bytes_pattern)
    wechatwindll_module = process.module_from_name(pm.process_handle, "WeChatWin.dll")
    wechat_id_addrs = pattern.pattern_scan_module(
        pm.process_handle, wechatwindll_module, id_pattern, return_multiple=True)
    if wechat_id_addrs == None or len(wechat_id_addrs) != 2:
        print(f"未能寻获微信账号: {id}")
        error()

    return wechat_id_addrs[1] - (64 if is64Bit(pm) else 36)


def getAesKey(pm, base, offset):
    try:
        if is64Bit(pm):
            result = pm.read_bytes(base + offset, 8)    # 读取 AES Key 的地址
            addr = struct.unpack("<Q", result)[0]       # 地址为小端 8 字节整型
        else:
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
    "3.9.0.28": 0x2E2D1AC,
    "3.9.2.23": 0x2FFD90C,
}

AESKEY_OFFSETS_64 = {
    "3.9.5.91": 0x3ACCC70
}

if __name__ == "__main__":
    try:
        pm = Pymem("WeChat.exe")
    except Exception as e:
        print(f"{e}，请确认微信程序已经打开并登录！")
        error()

    ap = argparse.ArgumentParser()
    ap.add_argument("-i", "--id", required=False, help="微信号，通过微信号来获取密钥偏移")
    args = vars(ap.parse_args())

    version, base = getVersionBase(pm)
    print(f"微信版本：{version} " + ("(64bit)" if is64Bit(pm) else "(32bit)"))
    print(f"微信基址：{hex(base)}")

    wechatid = args["id"]
    if wechatid != None:
        print(f"使用微信账号 {wechatid} 搜索")
        offset = getOffsetByWxNum(pm, wechatid) - base
    else:
        if is64Bit(pm):
            offset = AESKEY_OFFSETS_64.get(version, None)
        else:
            offset = AESKEY_OFFSETS.get(version, None)

        if not offset:
            print(f"暂不支持版本 {version}，请联系作者。")
            error()

    print(f"偏移地址：{hex(offset)}")

    aesKey = getAesKey(pm, base, offset)
    print(f"数据库密钥：{aesKey}")
