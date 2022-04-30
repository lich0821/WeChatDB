#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import pymem
import struct
import binascii


AESKEY_OFFSET = 0x1DDF914
WECHAT_VERSION = "3.3.0.115"


def getAesKey(p):
    # 获取 WeChatWin.dll 的基地址
    base_address = pymem.process.module_from_name(p.process_handle, "wechatwin.dll").lpBaseOfDll

    # 读取 AES Key 的地址
    result = p.read_bytes(base_address + AESKEY_OFFSET, 4)
    addr = struct.unpack("<I", result)[0]

    # 读取 AES Key
    aesKey = p.read_bytes(addr, 0x20)

    # 解码
    result = binascii.b2a_hex(aesKey)
    return base_address, result.decode()


if __name__ == "__main__":
    print(f"微信版本为：{WECHAT_VERSION}\n密钥偏移地址为：{hex(AESKEY_OFFSET)}")
    p = pymem.Pymem()
    p.open_process_from_name("WeChat.exe")
    base_offset, aesKey = getAesKey(p)
    print(f"数据库密钥为：{aesKey}")
