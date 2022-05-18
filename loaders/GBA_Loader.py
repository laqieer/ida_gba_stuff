'''
Thank's to SiD3W4y/GhidraGBA and LIJI32/gameboy.py

@thorodin-roth

Ported to IDA 7.7 by laqieer
'''

import idaapi
import ida_idp
import idc
import struct
import ida_funcs
import ida_bytes
import ida_lines

ROM_SIGNATURE_OFFSET = 0xb2
ROM_SIGNATURE        = b"\x96"
Nintendo_ROM_SIGNATURE_OFFSET 	= 4
Nintendo_ROM_SIGNATURE 	= b"\x24\xFF\xAE\x51"
RomFormatName        = "Game Boy Advance ROM: ARM7TDMI"
SIZE_HEADER		= 0xC0
ROM_SIZE		= 0x01000000
ROM_START		= 0x08000000
EntryPoint = 0x8000000

def accept_file(li, filename):
    li.seek(Nintendo_ROM_SIGNATURE_OFFSET)
    if li.read(4) != Nintendo_ROM_SIGNATURE:
        return 0

    li.seek(ROM_SIGNATURE_OFFSET)
    if li.read(1) != ROM_SIGNATURE:
        return 0
    return {'format': RomFormatName, 'processor':'arm'}


def create_data_labled(ea,name, item_size):
    if item_size == 4:
        item_type = ida_bytes.FF_DWORD
    elif item_size == 8:
        item_type = ida_bytes.FF_QWORD
    elif item_size == 2:
        item_type = ida_bytes.FF_WORD
    else:
        raise ValueError("Invalid item size")

    ida_bytes.create_data(ea, item_type, item_size, idaapi.BADADDR)
    idc.set_name(ea, name, idc.SN_NOCHECK | idc.SN_NOWARN)
  

def add_seg(startea, size, name,bitness=0,seg_cls="CONST",base=0,patch_bytes=None):
    s = idaapi.segment_t()
    s.start_ea = startea 
    s.end_ea   = startea + size 
    s.sel      = idaapi.setup_selector(base * 0x1000)
    s.bitness  = bitness
    s.align    = idaapi.saRelPara
    s.comb     = idaapi.scPub
    s.type = idaapi.SEG_DATA if seg_cls == "CONST" else  idaapi.SEG_CODE
    s.perm = idaapi.SEGPERM_EXEC | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_READ
    idaapi.add_segm_ex(s, name, seg_cls, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)
    if patch_bytes != None :
        for i in range(0,size):
            ida_bytes.patch_byte(startea + i,patch_bytes)
    
def load_file(li, neflags, format):
    if format != RomFormatName:
        Warning("Unkown format name: '%s'" % format)
        return 0

    size = li.size()
    idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER |ida_idp.SETPROC_LOADER_NON_FATAL|ida_idp.SETPROC_LOADER)
    idaapi.set_target_assembler(1)  
    entry_form_ea,entry_to_ea = (EntryPoint,EntryPoint + size)
    try:
        add_seg(0x0000000, 0x4000,"BIOS",seg_cls="CODE",bitness=1,patch_bytes=0)
        add_seg(0x2000000, 0x40000,"WRAM",patch_bytes=0)
        add_seg(0x3000000, 0x08000,"IRAM",bitness=1,patch_bytes=0)
        add_seg(0x4000000, 0x00400,"IO",bitness=1,patch_bytes=0)
        add_seg(0x5000000, 0x00400,"OBJ",patch_bytes=0)
        add_seg(0x6000000, 0x18000,"VRAM",patch_bytes=0)
        add_seg(0x7000000, 0x00400,"OAM",bitness=1,patch_bytes=0)
        add_seg(0x8000000, 0x2000000,"ROM",seg_cls="CODE")

        #init Entry point
        li.file2base(0, entry_form_ea, entry_to_ea, 1)
        ida_funcs.add_func(entry_form_ea)
        idaapi.add_entry(EntryPoint, EntryPoint, "start", 1)
        idaapi.cvar.inf.startIP = EntryPoint
        idaapi.cvar.inf.beginEA = EntryPoint

        ida_lines.add_extra_cmt(ROM_START, True, "ROM HEADER")

        create_data_labled(0x4000000, "DISPCNT",2)
        create_data_labled(0x4000004, "DISPSTAT",2)
        create_data_labled(0x4000006, "VCOUNT",2)
        create_data_labled(0x4000008, "BG0CNT",2)
        create_data_labled(0x400000A, "BG1CNT",2)
        create_data_labled(0x400000C, "BG2CNT",2)
        create_data_labled(0x400000E, "BG3CNT",2)
        create_data_labled(0x4000010, "BG0HOFS",2)
        create_data_labled(0x4000012, "BG0VOFS",2)
        create_data_labled(0x4000014, "BG1HOFS",2)
        create_data_labled(0x4000016, "BG1VOFS",2)
        create_data_labled(0x4000018, "BG2HOFS",2)
        create_data_labled(0x400001A, "BG2VOFS",2)
        create_data_labled(0x400001C, "BG3HOFS",2)
        create_data_labled(0x400001E, "BG3VOFS",2)
        create_data_labled(0x4000020, "BG2PA",2)
        create_data_labled(0x4000022, "BG2PB",2)
        create_data_labled(0x4000024, "BG2PC",2)
        create_data_labled(0x4000026, "BG2PD",2)
        create_data_labled(0x4000028, "BG2X",4)
        create_data_labled(0x400002C, "BG2Y",4)
        create_data_labled(0x4000030, "BG3PA",2)
        create_data_labled(0x4000032, "BG3PB",2)
        create_data_labled(0x4000034, "BG3PC",2)
        create_data_labled(0x4000036, "BG3PD",2)
        create_data_labled(0x4000038, "BG3X",4)
        create_data_labled(0x400003C, "BG3Y",4)
        create_data_labled(0x4000040, "WIN0H",2)
        create_data_labled(0x4000042, "WIN1H",2)
        create_data_labled(0x4000044, "WIN0V",2)
        create_data_labled(0x4000046, "WIN1V",2)
        create_data_labled(0x4000048, "WININ",2)
        create_data_labled(0x400004A, "WINOUT",2)
        create_data_labled(0x400004C, "MOSAIC",2)
        create_data_labled(0x4000050, "BLDCNT",2)
        create_data_labled(0x4000052, "BLDALPHA",2)
        create_data_labled(0x4000054, "BLDY",2)
        create_data_labled(0x4000060, "SOUND1CNT_L",2)
        create_data_labled(0x4000062, "SOUND1CNT_H",2)
        create_data_labled(0x4000064, "SOUND1CNT_X",2)
        create_data_labled(0x4000068, "SOUND2CNT_L",2)
        create_data_labled(0x400006C, "SOUND2CNT_H",2)
        create_data_labled(0x4000070, "SOUND3CNT_L",2)
        create_data_labled(0x4000072, "SOUND3CNT_H",2)
        create_data_labled(0x4000074, "SOUND3CNT_X",2)
        create_data_labled(0x4000078, "SOUND4CNT_L",2)
        create_data_labled(0x400007C, "SOUND4CNT_H",2)
        create_data_labled(0x4000080, "SOUNDCNT_L",2)
        create_data_labled(0x4000082, "SOUNDCNT_H",2)
        create_data_labled(0x4000084, "SOUNDCNT_X",2)
        create_data_labled(0x4000088, "SOUNDBIAS",2)
        create_data_labled(0x4000090, "WAVE_RAM",2)
        create_data_labled(0x40000A0, "FIFO_A",2)
        create_data_labled(0x40000A4, "FIFO_B",2)
        create_data_labled(0x40000B0, "DMA0SAD",4)
        create_data_labled(0x40000B4, "DMA0DAD",4)
        create_data_labled(0x40000B8, "DMA0CNT_L",2)
        create_data_labled(0x40000BA, "DMA0CNT_H",2)
        create_data_labled(0x40000BC, "DMA1SAD",4)
        create_data_labled(0x40000C0, "DMA1DAD",4)
        create_data_labled(0x40000C4, "DMA1CNT_L",2)
        create_data_labled(0x40000C6, "DMA1CNT_H",2)
        create_data_labled(0x40000C8, "DMA2SAD",4)
        create_data_labled(0x40000CC, "DMA2DAD",4)
        create_data_labled(0x40000D0, "DMA2CNT_L",2)
        create_data_labled(0x40000D2, "DMA2CNT_H",2)
        create_data_labled(0x40000D4, "DMA3SAD",4)
        create_data_labled(0x40000D8, "DMA3DAD",4)
        create_data_labled(0x40000DC, "DMA3CNT_L",2)
        create_data_labled(0x40000DE, "DMA3CNT_H",2)
        create_data_labled(0x4000100, "TM0CNT_L",2)
        create_data_labled(0x4000102, "TM0CNT_H",2)
        create_data_labled(0x4000104, "TM1CNT_L",2)
        create_data_labled(0x4000106, "TM1CNT_H",2)
        create_data_labled(0x4000108, "TM2CNT_L",2)
        create_data_labled(0x400010A, "TM2CNT_H",2)
        create_data_labled(0x400010C, "TM3CNT_L",2)
        create_data_labled(0x400010E, "TM3CNT_H",2)
        create_data_labled(0x4000120, "SIODATA32",4)
        create_data_labled(0x4000120, "SIOMULTI0",2)
        create_data_labled(0x4000122, "SIOMULTI1",2)
        create_data_labled(0x4000124, "SIOMULTI2",2)
        create_data_labled(0x4000126, "SIOMULTI3",2)
        create_data_labled(0x4000128, "SIOCNT",2)
        create_data_labled(0x400012A, "SIOMLT_SEND",2)
        create_data_labled(0x400012A, "SIODATA8",2)
        create_data_labled(0x4000130, "KEYINPUT",2)
        create_data_labled(0x4000132, "KEYCNT",2)
        create_data_labled(0x4000200, "IE",2)
        create_data_labled(0x4000202, "IF",2)
        create_data_labled(0x4000204, "WAITCNT",2)
        create_data_labled(0x4000208, "IME",2)
        create_data_labled(0x4000300, "POSTFLG",2)
        create_data_labled(0x4000301, "HALTCNT",2)
        create_data_labled(0x4000134, "RCNT",2)
        create_data_labled(0x4000136, "IR",2)
        create_data_labled(0x4000140, "JOYCNT",2)
        create_data_labled(0x4000150, "JOY_RECV",4)
        create_data_labled(0x4000154, "JOY_TRANS",4)
        create_data_labled(0x4000158, "JOYSTAT",2)
        idc.set_name(0x08000004, "rom_header", idc.SN_NOCHECK)
        idc.set_name(0x080000C0, "init_vector", idc.SN_NOCHECK)
        print("Your Game Boy Advance Loaded OK")
        return 1
    except Exception as e: 
        print(e)