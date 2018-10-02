# proc used in fire emblem
# by laqieer
# 2018-10-01

from ida_gba import *
from idaapi import *
from idc import *
from idautils import *

proc_create_functions = {
        'AFEJ':0x8003A04, #FE6
        'AE7J':0x8004370, #FE7J
        'AE7E':0x8004494, #FE7U
        'BE8J':0x8002BCC, #FE8J
        'BE8E':0x8002C7C, #FE8U
    }

def get_proc_create_function():
    """
    Get the address of CreateProc()
    """
    return proc_create_functions[get_game_code()]

def get_proc_create_function_blocking():
    """
    Get the address of CreateProcBlocking()
    """
    return 0x64 + proc_create_functions[get_game_code()]

def get_all_procs():
    """
    Get the address of all procs in the rom
    """
    proc_list = []
    
    for xref in XrefsTo(get_proc_create_function()):
        if xref.type == fl_CN or xref.type == fl_CF:
            for i in DataRefsFrom(xref.frm - 4):
                for proc_addr in DataRefsFrom(i):
                    if proc_list.count(proc_addr) == 0:
                        proc_list.append(proc_addr)

    for xref in XrefsTo(get_proc_create_function_blocking()):
        if xref.type == fl_CN or xref.type == fl_CF:
            for i in DataRefsFrom(xref.frm - 4):
                for proc_addr in DataRefsFrom(i):
                    if proc_list.count(proc_addr) == 0:
                        proc_list.append(proc_addr)

    return proc_list

def show_procs_info():
    """
    Show the total num and range of procs in the game
    """
    proc_list = get_all_procs()
    print "%d procs in total: from 0x%X to 0x%X" % (len(proc_list), min(proc_list), max(proc_list))
def get_end_addr(ea):
    """
    Get end address of a proc
    """
    return find_binary(ea, SEARCH_DOWN, "00 00 00 00 00 00 00 00")

def make_proc(ea):
    """
    Make proc at a specific address
    """
    create_struct(ea, 8, "proc")
    end = get_end_addr(ea)
    make_array(ea, (end - ea) / 8 + 1)

def make_all_procs():
    """
    Make all procs in the game
    """
    proc_list = get_all_procs()
    for proc_addr in proc_list:
        make_proc(proc_addr)
        
def get_all_functions_in_proc(ea):
    """
    Get all functions in a proc
    """
    functions = []
    end = get_end_addr(ea)
    for addr in range (ea, end, 4):
        if get_dword(addr) in (2, 3, 4):
            func = get_dword(addr + 4) & 0x9FFFFFE
            if func not in functions:
                functions.append(func)
    return functions

def make_all_functions_in_proc(ea):
    """
    Make all functions in a proc
    """
    for func in get_all_functions_in_proc(ea):
        MakeFunction(func)
        
def make_all_functions_in_all_procs():
    """
    Make all functions in all procs
    """
    for proc in get_all_procs():
        make_all_functions_in_proc(proc)

def name_proc(ea):
    """
    Name a proc
    """
    if get_dword(ea) == 1:
        set_name(ea, "proc_%s" % GetString(get_dword(ea+4)))

def name_all_procs(ea):
    """
    Name all procs in the game
    """
    for proc in get_all_procs():
        name_proc(proc)

def main():
    procs = get_all_procs()
    print "%d procs in total: from 0x%X to 0x%X" % (len(procs), min(procs), max(procs))
    for proc in procs:
        name_proc(proc)
        make_proc(proc)
        make_all_functions_in_proc(proc)

if __name__ == "__main__":
    main()
        
