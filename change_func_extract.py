#!/usr/bin/env python

'''
Author: Chase Schultz
Purpose: Function Hooking using IDAPython
Usage: Code Coverage Statistics

'''
import sys
from idaapi import *
import idautils


class HitLog():
    ''' Data Structure '''

    def __init__(self, NameOfFunction, FunctionAddress):
        self.functionName = NameOfFunction
        self.functionAddress = FunctionAddress
        self.hitCount = 0

    def getNameOfFunction(self):
        return self.functionName

    def getFunctionAddress(self):
        return self.functionAddress

    def getHitCount(self):
        return self.hitCount

    def incHitCount(self):
        self.hitCount += 1


class StatLog():

    def __init__(self):
        self.hitDictionary = {}
        self.totalHitCount = 0

    def addHit(self, functionName, functionAddress):
        ''' Add a hit to our hitDictionary or increment hitCounter for particular hitLog '''
        self.totalHitCount += 1
        if(self.hitDictionary.has_key(functionAddress)):
            hitLogInstance = self.hitDictionary[functionAddress]
            hitLogInstance.incHitCount()
        else:
            hitLogInstance = HitLog(functionName, functionAddress)
            hitLogInstance.incHitCount()
            self.hitDictionary[functionAddress] = hitLogInstance

    def getHitDict(self):
        ''' Get the Dictionary containing the HitLog'''
        return self.hitDictionary

    def __logToFile__(self, message):
        ''' Logs data to a file '''
        fileDescriptor = open("changed_function_hit_list.txt", "a")
        fileDescriptor.write(message)
        fileDescriptor.close()

    def outputStatLog(self):
        ''' To be called after script has run, for the breakpoint
         statistics to be appended to file and printed output window '''
        print "\n\n\tFunction Code Coverage Statistics\n"
        print "====================================================="
        print "<Function Address>\t<Function Name>\t<Hit Count>\t<Percentage of Hits>\n"

        self.__logToFile__("\n\n\tFunction Code Coverage Statistics\n")
        self.__logToFile__("====================================================\n=")
        self.__logToFile__("<Function Address>\t<Function Name>\t<Hit Count>\t\t<Percentage of Hits>\n")

        for functionAddress, hitLog in self.hitDictionary.iteritems():
            print "%s\t%s\t%s\t%.02f\n" % (functionAddress, hitLog.getNameOfFunction(), hitLog.getHitCount(), ((float(hitLog.getHitCount()) / float(self.totalHitCount)) * 100))
            self.__logToFile__("%s\t%s\t%s\t%.02f\n" % (functionAddress, hitLog.getNameOfFunction(), hitLog.getHitCount(), ((float(hitLog.getHitCount()) / float(self.totalHitCount)) * 100)))
        return


class DbgHook(DBG_Hooks):

    def __hooker__(self, ea):
        ''' Hooked Function Breakpoint - This is where we could be more specific about particular breakpoints'''
        currentAddress = ea
        functionAddress = hex(currentAddress)
        functionName = GetFunctionName(currentAddress)

        # Print that we executed a breakpoint
        print "================== changed_func Breakpoint Hit! ======================="
        print "Hit at address:\t 0x%s\n" % functionAddress
        print "Function Name:\t %s\n" % functionName

        # File Logging
        self.__logToFile__("%s %s\n" % (functionName, functionAddress))

        # Statistics Logging
        global statsticsLog
        statsticsLog.addHit(functionName, functionAddress)

        #continues the process once we've got information we want
        idaapi.continue_process()

    def __logToFile__(self, message):
        ''' Logs data to a file '''
        fileDescriptor = open("changed_function_hit_list.txt", "a")
        fileDescriptor.write(message)
        fileDescriptor.close()

    def dbg_bpt(self, tid, ea):
        ''' Breakpoint Callback '''
        self.__hooker__(ea)
        return 0


try:
    debughook.unhook()
except:
    print "Debug Hook not set yet..."

debughook = DbgHook()
debughook.hook()
statsticsLog = StatLog()
print "Installed debug hook ..."
