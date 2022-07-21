import frida
import sys
import click
import random

import pyperclip  # 剪贴板

from idc_bc695 import *
import idautils
import idaapi
import idc


def find_vert():

    flag = False

    hook_addr = ""

    # 通过string窗口查找关键函数
    sc = idautils.Strings()
    for s in sc:
        # print(str(s))
        if(str(s) == "VerifyCert"):
            for xref in idautils.XrefsTo(s.ea, 0):
                if(xref.frm == BADADDR or GetFunctionName((xref.frm)) == ""):
                    pass
                else:
                    # 获取函数的引用和被引用处的地址
                    #print(xref.type, XrefTypeName(xref.type), 'from', hex(xref.frm), 'to', hex(xref.to))
                    # 数据发送到剪贴板
                    # pyperclip.copy( GetFunctionName(xref.frm))
                    # 获取函数名
                    # sub_name = GetFunctionName(xref.frm)
                    # 获取函数起始地址
                    hook_addr = hex(idc.GetFunctionAttr(
                        xref.frm, FUNCATTR_START))
                    # print("start:", hex(start))
                    flag = True
        else:
            pass

    if(flag):
        #print("[+] 已粘贴到剪贴版.")
        return hook_addr
    else:
        print("[+++++++] 没找到过抖音证书检测的地方！！")
        return


if __name__ == '__main__':
    name = find_vert()
    if(name != " "):
        print("name:", name)
