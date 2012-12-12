#!/usr/bin/env python

'''
Author: Chase Schultz
Purpose: Function Hooking using IDAPython
Usage: Uses names of functions to set breakpoints
       Possible other uses - (code coverage)
Reference: Grey Hat Python - IDAPython Scripting Chapter
'''

from idaapi import *
import idautils


class PyConditionalHook():

    def __init__(self):
        pass

    def set_bp(self, address, cnd):

        global cond_file

        print "[+] Setting conditional IDAPython breakpoint on %08x" % address
        print "================= Breakpoint Added ===================\n\n"
        add_bpt(address, 0, BPT_SOFT)
        enable_bpt(address, True)
        SetBptCnd(address, '')
        #AddBpt(address)
        #SetBptAttr(address, BPTATTR_FLAGS, 0x0)


#idaapi.CompileLine('static cond() {return (RunPythonStatement("hooker()") | Byte(0x10000));}')

ea = ScreenEA()
pythonHook = PyConditionalHook()
for function_ea in Functions(SegStart(ea), SegEnd(ea)):

    # Goes through IDA DB and adds breakpoints to functions that have a specific string in name.
    if("Ndr" in GetFunctionName(function_ea)):
        print "================= Adding Breakpoint @ 0x%s =======" % hex(function_ea)
        print "Function Name:\t%s\nFunction Address:\t0x%s" % (GetFunctionName(function_ea), hex(function_ea))
        pythonHook.set_bp(function_ea, '')
