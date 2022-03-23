import keystone
from capstone import *
import idc
import ida_bytes
import subprocess



'''
设置arm架构


'''

arch = keystone.KS_ARCH_ARM
mode = keystone.KS_MODE_THUMB
ks = keystone.Ks(arch, mode)
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


'''
判断是否是BLX sub_4094 代码
'''
def is_BLX_sub4094(ea):
    ldr_addr = ea
    ldr_flag = idc.get_full_flags(ldr_addr) #得到这个地址的属性

    #判断地址的属性
    if not idc.is_code(ldr_flag):
        return False

    #获取助记符
    if idc.print_insn_mnem(ldr_addr) != "BLX":
        return False
    
    #判断操作数
    if idc.print_operand(ldr_addr,0) != "sub_4094":
        return False

    if idc.print_insn_mnem(ldr_addr -2) != "PUSH":
        return False

    if idc.print_insn_mnem(ldr_addr+8) != "POP":
        return False

    return True 



def is_BLX_sub407C(ea):
    ldr_addr = ea
    ldr_flags = idc.get_full_flags(ldr_addr)
    if not idc.is_code(ldr_flags):
        return False
 
    if idc.print_insn_mnem(ldr_addr) != 'BLX':
        return False
 
    if idc.print_operand(ldr_addr, 0) != 'sub_407C':
        return False

    return True


def func_patch():
    #从0地址开始搜索
    ins_addr = idc.next_head(0)
    while ins_addr != idc.BADADDR:
        if is_BLX_sub407C(ins_addr):
            print("ins_addr: ",hex(ins_addr))
            #如果是调用sub407C的地址 第一次找到的应该是sub_3440
            for i in CodeRefsTo(ins_addr, False):
                if idc.get_wide_word(i+4) == 0x46C0: #这里比如是在地址.text:000034BA  DCW 0x46C0 中间有nop
                    index = idc.get_wide_dword(i+6) #得到索引值 索引应该是0
                    patch_qword(i+6,0x46C046C0)
                    idc.create_insn(i+6)
                else:
                    index = idc.get_wide_dword(i+4)
                    patch_qword(i+4,0x46C046C0)
                    idc.create_insn(i+4)
                
                print("i: " +hex(i)+ " index: "+hex(index) )
                
                index = index *4 + ins_addr+4 #加4 是因为lr寄存器是sub_407C的下一个指令的值
                offset = ida_bytes.get_dword(index) #获取到地址的值0x10 0x16 0x64 0x80
                target = ins_addr + 0x4 + offset #要跳转去的地址
                command = "BL "+ hex(target) #因为跳转地址没有超过255 所以可以跳转
                pi = subprocess.Popen(['D:\\360极速浏览器下载\\keystone-0.9.2-win64\\kstool.exe', 'thumb', command, \
                hex(i)], shell=True, stdout=subprocess.PIPE) #将command 转成对应的机器码
                output = pi.stdout.read()
                ins = str(output[-15:-4])[2:-1]
                ins = ins.split(" ")
                ins = "0x" + ins[3] + ins[2] + ins[1] + ins[0] #机器码的16进制
                print("ins:" + ins)
                patch_dword(i, int(ins, 16))
        elif is_BLX_sub4094(ins_addr):
            print("ins_addr: ",hex(ins_addr))
            patch_dword(ins_addr - 2, 0xbf00)
            patch_dword(ins_addr, 0xbf00)
            patch_dword(ins_addr + 2, 0xbf00)
            patch_dword(ins_addr + 4, 0xbf00)
            patch_dword(ins_addr + 6, 0xbf00)
            patch_dword(ins_addr + 8, 0xbf00)

        ins_addr = idc.next_head(ins_addr)#指令不断增长
func_patch()






