"""
This script should be used within Immunity Debugger.
It monitors API calls associated with malicious activity
and reports it to a window.
"""

__VERSION__ = '1.0'

import immlib
from immlib import LogBpHook

#TODO: Check that all API arguments have been logged correctly
#TODO: Add option to BP on A call or W call (or just switch all A calls to W)
#TODO: Add more keylogg stuff
#TODO: Add resource stuff

#########################################################################
"""
regMon Hooks
"""
class RegOpenKeyExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = ["RegOpenKeyExA", "("]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP']+ 0x4 )
        logItems = [ "", "hKey = \"%s\"" % (hKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpSubKey = imm.readString( ptr )
        logItems = [ "", "lpSubKey = \"%s\"" % (lpSubKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ulOptions = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "ulOptions = \"0x%08x\"" % (ulOptions) ]
        regMonWin.add( regs['EIP'], logItems )

        samDesired = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "samDesired = \"0x%08x\"" % (samDesired) ]
        regMonWin.add( regs['EIP'], logItems )

        phkResult = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "phkResult = \"0x%08x\"" % (phkResult) ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )

class RegCreateKeyExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = [ "RegCreateKeyExA", "(" ]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hKey = \"%s\"" % (hKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpSubKey = imm.readString( ptr )
        logItems = [ "", "lpSubKey = \"%s\"" % (lpSubKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpClass = imm.readString( ptr )
        logItems = [ "", "lpClass = \"%s\"" % (lpClass) ]
        regMonWin.add( regs['EIP'], logItems )

        dwOptions = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwOptions = \"0x%08x\"" % (dwOptions) ]
        regMonWin.add( regs['EIP'], logItems )

        samDesired = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "samDesired = \"0x%08x\"" % (samDesired) ]
        regMonWin.add( regs['EIP'], logItems )

        lpSecurityAttributes = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "lpSecurityAttributes = \"0x%08x\"" % (lpSecurityAttributes) ]
        regMonWin.add( regs['EIP'], logItems )

        phkResult = imm.readLong( regs['ESP'] + 0x1c )
        logItems = [ "", "phkResult = \"0x%08x\"" % (phkResult) ]
        regMonWin.add( regs['EIP'], logItems )

        lpdwDisposition = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "lpdwDisposition = \"0x%08x\"" % (lpdwDisposition) ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )

class RegQueryValueExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = [ "RegQueryValueExA", "(" ]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hKey = \"%s\"" % (hKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpValueName = imm.readString( ptr )
        logItems = [ "", "lpValueName = \"%s\"" % (lpValueName) ]
        regMonWin.add( regs['EIP'], logItems )

        lpType = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpType = \"0x%08x\"" % (lpType) ]
        regMonWin.add( regs['EIP'], logItems )

        lpData = imm.readShort( regs['ESP'] + 0x10 )
        logItems = [ "", "lpData = \"0x%08x\"" % (lpData) ]
        regMonWin.add( regs['EIP'], logItems )

        lpcbData = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpcbData = \"0x%08x\"" % (lpcbData) ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )

class RegSetValueExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = [ "RegSetValueExA", "(" ]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hKey = \"%s\"" % (hKey) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpValueName = imm.readString( ptr )
        logItems = [ "", "lpValueName = \"%s\"" % (lpValueName) ]
        regMonWin.add( regs['EIP'], logItems )

        dwType = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwType = \"0x%08x\"" % (dwType) ]
        regMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10)
        lpData = imm.readString( ptr )
        logItems = [ "", "lpData = \"%s\"" % (lpData) ]
        regMonWin.add( regs['EIP'], logItems )

        cbData = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "cbData = \"0x%08x\"" % (cbData) ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )

class RegCloseKey(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = [ "RegCloseKey", "(" ]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hKey = \"%s\"" % (hKey) ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )

class RegConnectRegistryA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        regMonWin = imm.getKnowledge( "regMonWin" )

        logItems = [ "RegConnectRegistryA", "(" ]
        regMonWin.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpMachineName = imm.readString( ptr )
        logItems = [ "", "lpMachineName = \"%s\"" % (lpMachineName)]
        regMonWin.add( regs['EIP'], logItems )

        hKey = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "hKey = \"0x%08x\"" % (hKey)]
        regMonWin.add( regs['EIP'], logItems )

        phkResult = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "phKey = \"0x%08x\"" % (phkResult)]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        regMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        regMonWin.add( regs['EIP'], logItems )


#########################################################################
"""
fileMon Hooks
"""
class CreateFileA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = [ "CreateFileA", "(" ]
        fileMonWin.add( regs['EIP'],logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpFileName = imm.readString( ptr )
        logItems = [ "", "lpFileName = \"%s\"" % (lpFileName) ]
        fileMonWin.add( regs['EIP'],logItems )

        dwDesiredAccess = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwDesiredAccess = \"0x%08x\"" % (dwDesiredAccess) ]
        fileMonWin.add( regs['EIP'],logItems )

        dwShareMode = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwShareMode = \"0x%08x\"" % (dwShareMode) ]
        fileMonWin.add( regs['EIP'],logItems )

        lpSecurityAttributes = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpSecurityAttributes = \"0x%08x\"" % (lpSecurityAttributes) ]
        fileMonWin.add( regs['EIP'],logItems )

        dwCreationDisposition = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "dwCreationDisposition = \"0x%08x\"" % (dwCreationDisposition) ]
        fileMonWin.add( regs['EIP'],logItems )

        dwFlagsAndAttributes = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwFlagsAndAttributes = \"0x%08x\"" % (dwFlagsAndAttributes) ]
        fileMonWin.add( regs['EIP'],logItems )

        hTemplateFile = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "hTemplateFile = \"0x%08x\"" % (hTemplateFile) ]
        fileMonWin.add( regs['EIP'],logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'],logItems )

        logItems = [ "", "" ]
        fileMonWin.add( regs['EIP'],logItems )

class ReadFile(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = [ "ReadFile", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        fileMonWin.add( regs['EIP'], logItems )

        nNumberOfBytesToRead = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "nNumberOfBytesToRead = \"0x%08x\"" % (nNumberOfBytesToRead) ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpNumberOfBytesRead = imm.readLong( ptr )
        logItems = [ "", "lpNumberOfBytesRead = \"0x%08x\"" % (lpNumberOfBytesRead) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpOverlapped = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpOverlapped = \"0x%08x\"" % (lpOverlapped) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        fileMonWin.add( regs['EIP'], logItems )

class ReadFileEx(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = [ "ReadFileEx", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        fileMonWin.add( regs['EIP'], logItems )

        nNumberOfBytesToRead = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "nNumberOfBytesToRead = \"0x%08x\"" % (nNumberOfBytesRead) ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpNumberOfBytesRead = imm.readLong( ptr )
        logItems = [ "", "lpNumberOfBytesRead = \"0x%08x\"" % (lpNumberOfBytesRead) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpOverlapped = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpOverlapped = \"0x%08x\"" % (lpOverlapped) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpCompletionRoutine = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "lpCompletionRoutine = \"0x%08x\"" % (lpCompletionRoutine) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        fileMonWin.add( regs['EIP'], logItems )

class WriteFile(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = [ "WriteFile", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        fileMonWin.add( regs['EIP'], logItems )

        nNumberOfBytesToWrite = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "nNumberOfBytesToWrite = \"0x%08x\"" % (nNumberOfBytesToWrite) ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpNumberOfBytesWritten = imm.readLong( ptr )
        logItems = [ "", "lpNumberOfBytesWritten = \"0x%08x\"" % (lpNumberOfBytesWritten) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpOverlapped = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpOverlapped = \"0x%08x\"" % (lpOverlapped) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        fileMonWin.add( regs['EIP'], logItems )

class WriteFileEx(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = [ "WriteFileEx", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        fileMonWin.add( regs['EIP'], logItems )

        nNumberOfBytesToWrite = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "nNumberOfBytesToWrite = \"0x%08x\"" % (nNumberOfBytesToWrite) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpOverlapped = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpOverlapped = \"0x%08x\"" % (lpOverlapped) ]
        fileMonWin.add( regs['EIP'], logItems )

        lpCompletionRoutine = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpCompletionRoutine = \"0x%08x\"" % (lpCompletionRoutine) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        fileMonWin.add( regs['EIP'], logItems )

class DeleteFileA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )


        logItems = ["DeleteFileA", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpFileName = imm.readString( ptr )
        logItems = [ "", "lpFileName = '%s'" % (lpFileName) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        fileMonWin.add( regs['EIP'], logItems )

class MoveFileEx(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        fileMonWin = imm.getKnowledge( "fileMonWin" )

        logItems = ["MoveFileExA", "(" ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpExistingFileName = imm.readString( ptr )
        logItems = [ "", "lpExistingFileName = '%s'" % (lpExistingFileName) ]
        fileMonWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpNewFileName = imm.readString( ptr )
        logItems = [ "", "lpNewFileName = '%s'" % (lpNewFileName) ]
        fileMonWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0xC)
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        fileMonWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        fileMonWin.add( regs['EIP'], logItems )

#########################################################################
"""
dnsRequests Hooks
"""
class DnsQuery_A(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        dnsRequest = imm.getKnowledge( "dnsRequest" )

        logItems = [ "DnsQuery_A", "(" ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpstrName = imm.readString( ptr )
        logItems = [ "", "lpstrName = \"%s\"" % (lpstrName) ]
        dnsRequest.add( regs['EIP'], logItems)

        wType = imm.readShort( regs['ESP'] + 0x8 )
        logItems = [ "", "wType = \"0x%08x\"" % (wType) ]
        dnsRequest.add( regs['EIP'], logItems)

        fOptions = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "fOptions = \"0x%08x\"" % (fOptions) ]
        dnsRequest.add( regs['EIP'], logItems)

        aipServers = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "aipServers = \"0x%08x\"" % (aipServers) ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        ptrPtr = imm.readLong( ptr )
        ppQueryResultSet = imm.readString( ptrPtr )
        logItems = [ "", "ppQueryResultSet = \"%s\"" % (ppQueryResultSet) ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ")" ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ""]
        dnsRequest.add( regs['EIP'], logItems)

class DnsQuery_W(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        dnsRequest = imm.getKnowledge( "dnsRequest" )

        logItems = [ "DnsQuery_W", "(" ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpstrNameW = imm.readWString( ptr )
        lpstrName = getASCII( lpstrNameW )

        logItems = [ "", "lpstrName = \"%s\"" % (lpstrName) ]
        dnsRequest.add( regs['EIP'], logItems)

        wType = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "wType = \"0x%08x\"" % (wType) ]
        dnsRequest.add( regs['EIP'], logItems)

        fOptions = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "fOptions = \"0x%08x\"" % (fOptions) ]
        dnsRequest.add( regs['EIP'], logItems)

        aipServers = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "aipServers = \"0x%08x\"" % (aipServers) ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        ptrPtr = imm.readLong( ptr )
        ppQueryResultSetW = imm.readWString( ptrPtr )
        ppQueryResultSet = getASCII( ppQueryResultSetW )

        logItems = [ "", "ppQueryResultSet = \"%s\"" % (ppQueryResultSet) ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ")" ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ""]
        dnsRequest.add( regs['EIP'], logItems)

class DnsQuery_UTF8(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        dnsRequest = imm.getKnowledge( "dnsRequest" )

        logItems = [ "DnsQuery_UTF8", "(" ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpstrName = imm.readString( ptr )
        logItems = [ "", "lpstrName = \"%s\"" % (lpstrName) ]
        dnsRequest.add( regs['EIP'], logItems)

        wType = imm.readShort( regs['ESP'] + 0x8 )
        logItems = [ "", "wType = \"0x%08x\"" % (wType) ]
        dnsRequest.add( regs['EIP'], logItems)

        fOptions = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "fOptions = \"0x%08x\"" % (fOptions) ]
        dnsRequest.add( regs['EIP'], logItems)

        aipServers = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "aipServers = \"0x%08x\"" % (aipServers) ]
        dnsRequest.add( regs['EIP'], logItems)

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        ptrPtr = imm.readLong( ptr )
        ppQueryResultSet = imm.readString( ptrPtr )
        logItems = [ "", "ppQueryResultSet = \"%s\"" % (ppQueryResultSet) ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ")" ]
        dnsRequest.add( regs['EIP'], logItems)

        logItems = [ "", ""]
        dnsRequest.add( regs['EIP'], logItems)

#########################################################################
"""
generalSocketComm Hooks
"""
class WSAStartup(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        logItems = ["WSAStartup", "(" ]
        sendRecvWin.add( regs['EIP'], logItems )

        wVersionRequested = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "wVersionRequested = \"0x%08x\"" % (wVersionRequested) ]
        sendRecvWin.add( regs['EIP'], logItems )

        lpWSAData = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpWSAData = \"0x%08x\"" % (lpWSAData)]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        sendRecvWin.add( regs['EIP'], logItems )

class listen(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        logItems = [ "listen", "(" ]
        sendRecvWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        sendRecvWin.add( regs['EIP'], logItems )

        backlog = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "backlog = \"0x%08x\"" % (backlog)]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        sendRecvWin.add( regs['EIP'], logItems )

class connect(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        logItems = [ "connect", "(" ]
        sendRecvWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        sendRecvWin.add( regs['EIP'], logItems )

        name = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "name = \"0x%08x\"" % (name) ]
        sendRecvWin.add( regs['EIP'], logItems )

        namelen = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "namelen = \"0x%08x\"" % (namelen) ]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        sendRecvWin.add( regs['EIP'], logItems )

class accept(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        logItems = [ "accept", "(" ]
        sendRecvWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        sendRecvWin.add( regs['EIP'], logItems )

        addr = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "addr = \"0x%08x\"" % (addr) ]
        sendRecvWin.add( regs['EIP'], logItems )

        addrlen = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "addrlen = \"0x%08x\"" % (addrlen)]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        sendRecvWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        sendRecvWin.add( regs['EIP'], logItems )

class recv(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        s = imm.readLong( regs['ESP'] + 0x4 )
        buf = imm.readLong( regs['ESP'] + 0x8 )
        bufLen = imm.readLong( regs['ESP'] + 0xC )
        flags = imm.readLong( regs['ESP'] + 0x10)

        logItems = ["","recv: s = \"0x%08x\", buf = \"0x%08x\", bufLen = \"0x%08x\", flags = \"0x%08x\"" % (s, buf, bufLen, flags) ]
        sendRecvWin.add( regs['EIP'], logItems )

class recvfrom(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        s = imm.readLong( regs['ESP'] + 0x4 )
        buf = imm.readLong( regs['ESP'] + 0x8 )
        bufLen = imm.readLong( regs['ESP'] + 0xC )
        flags = imm.readLong( regs['ESP'] + 0x10 )
        fromBuf = imm.readLong( regs['ESP'] + 0x14 )
        fromLen = imm.readLong( regs['ESP'] + 0x18 )

        logItems = ["","recvfrom: s = \"0x%08x\", buf = \"0x%08x\", bufLen = \"0x%08x\", flags = \"0x%08x\", from = \"0x%08x\", fromLen = \"0x%08x\"" % (s, buf, bufLen, flags, fromBuf, fromLen) ]
        sendRecvWin.add( regs['EIP'], logItems )

class WSARecv(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        s = imm.readLong( regs['ESP'] + 0x4 )
        lpBuffers = imm.readLong( regs['ESP'] + 0x8 )
        dwBufferCount = imm.readLong( regs['ESP'] + 0xC )
        lpNumberOfBytesRecvd = imm.readLong( regs['ESP'] + 0x10 )
        lpFlags = imm.readLong( regs['ESP'] + 0x14 )
        lpOverlapped = imm.readLong( regs['ESP'] + 0x18 )
        lpCompletionRoutine = imm.readLong( regs['ESP'] + 0x1C )

        logItems = ["","WSARecv: s = \"0x%08x\", lpBuffers = \"0x%08x\", dwBufferCount = \"0x%08x\", lpNumberOfBytesRecvd = \"0x%08x\", lpFlags = \"0x%08x\", lpOverlapped = \"0x%08x\", lpCompletionRoutine = \"0x%08x\"" % (s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine) ]
        sendRecvWin.add( regs['EIP'], logItems )

class send(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        s = imm.readLong( regs['ESP'] + 0x4 )
        buf = imm.readLong( regs['ESP'] + 0x8 )
        bufLen = imm.readLong( regs['ESP'] + 0xC )
        flags = imm.readLong( regs['ESP'] + 0x10 )

        logItems = ["send: s = \"0x%08x\", buf = \"0x%08x\", len = \"0x%08x\", flags = \"0x%08x\"" % (s, buf, bufLen, flags),""]
        sendRecvWin.add( regs['EIP'], logItems )

class WSASend(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        sendRecvWin = imm.getKnowledge( "sendRecvWin" )

        s = imm.readLong( regs['ESP'] + 0x4 )
        lpBuffers = imm.readLong( regs['ESP'] + 0x8 )
        dwBufferCount = imm.readLong( regs['ESP'] + 0xC )
        lpNumberOfBytesSent = imm.readLong( regs['ESP'] + 0x10 )
        dwFlags = imm.readLong( regs['ESP'] + 0x14 )
        lpOverlapped = imm.readLong( regs['ESP'] + 0x18 )
        lpCompletionRoutine = imm.readLong( regs['ESP'] + 0x1C )

        logItems = ["WSASend: s = \"0x%08x\", lpBuffers = \"0x%08x\", dwBufferCount = \"0x%08x\", lpNumberOfBytesSent = \"0x%08x\", dwFlags = \"0x%08x\", lpOverlapped = \"0x%08x\", lpCompletionRoutine = \"0x%08x\"" % (s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine),""]
        sendRecvWin.add( regs['EIP'], logItems )

#########################################################################
"""
promiscuousMode Hooks
"""
class WSASocketA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        promiscuousModeWin = imm.getKnowledge( "promiscuousModeWin" )

        logItems = ["WSASocketA", "(" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        af = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "af = \"0x%08x\"" % (af) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        sockType = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "type = \"0x%08x\"" % (sockType) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        protocol = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "protocol = \"0x%08x\"" % (protocol) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpProtocolInfo = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpProtocolInfo = \"0x%08x\"" % (lpProtocolInfo) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        g = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "g = \"0x%08x\"" % (g) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        promiscuousModeWin.add( regs['EIP'], logItems )

class socket(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        promiscuousModeWin = imm.getKnowledge( "promiscuousModeWin" )

        logItems = [ "socket", "(" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        af = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "af = \"0x%08x\"" % (af) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        sockType = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "type = \"0x%08x\"" % (sockType) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        protocol = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "protocol = \"0x%08x\"" % (protocol) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

class bind(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        promiscuousModeWin = imm.getKnowledge( "promiscuousModeWin" )

        logItems = [ "bind", "(" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        promiscuousModeWin.add( regs['EIP'], logItems )
#still having a problem here, dont know why but it seems to
#cause a crash
#        name = imm.readLong( regs['ESP'] + 0x8)
#        logItems = [ "", "name = \"0x%08x\"" % (name) ]
#        promiscuousModeWin.add( regs['EIP'], logItems )

        namelen = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "namelen = \"0x%08x\"" % (namelen) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

class WSAIoctl(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        promiscuousModeWin = imm.getKnowledge( "promiscuousModeWin" )

        logItems = [ "WSAIoctl", "(" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        dwIoControlCode = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwIoControlCode = \"0x%08x\"" % (dwIoControlCode) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpvInBuffer = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpvInBuffer = \"0x%08x\"" % (lpvInBuffer) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        cbInBuffer = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "cbInBuffer = \"0x%08x\"" % (cbInBuffer) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpvOutBuffer = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpvOutBuffer = \"0x%08x\"" % (lpvOutBuffer) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        cbOutBuffer = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "cbOutBuffer = \"0x%08x\"" % (cbOutBuffer) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpcbBytesReturned = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "lpcbBytesReturned = \"0x%08x\"" % (lpcbBytesReturned) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpOverlapped = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "lpOverlapped = \"0x%08x\"" % (lpOverlapped) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        lpCompletionRoutine = imm.readLong( regs['ESP'] + 0x24 )
        logItems = [ "", "lpCompletionRoutine = \"0x%08x\"" % (lpCompletionRoutine) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

class ioctlsocket(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        promiscuousModeWin = imm.getKnowledge( "promiscuousModeWin" )

        logItems = ["ioctlsocket", "(" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        s = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "s = \"0x%08x\"" % (s) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        cmd = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "cmd = \"0x%08x\"" % (cmd) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        argp = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "argp = \"0x%08x\"" % (argp) ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        promiscuousModeWin.add( regs['EIP'], logItems )

#########################################################################
"""
packetSpoofing Hooks
"""
class PacketOpenAdapter(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        packetSpoofWin = imm.getKnowledge( "packetSpoofWin" )
        logItems = ["PacketOpenAdapter", "("]
        packetSpoofWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        AdapterName = imm.readString( ptr )
        logItems = [ "", "AdapterName = \"%s\"" % (AdapterName)]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        packetSpoofWin.add( regs['EIP'], logItems )

class PacketSetBuff(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        packetSpoofWin = imm.getKnowledge( "packetSpoofWin" )

        logItems = ["PacketSetBuff", "("]
        packetSpoofWin.add( regs['EIP'], logItems )

        AdapterObject = imm.readLong( regs['ESP'], 0x4 )
        logItems = [ "", "AdapterObject = \"0x%08x\"" % (AdapterObject)]
        packetSpoofWin.add( regs['EIP'], logItems )

        dim = imm.readLong( regs['ESP'], 0x8 )
        logItems = [ "", "dim = \"0x%08x\"" % (dim)]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        packetSpoofWin.add( regs['EIP'], logItems )


class PacketAllocatePacket(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        packetSpoofWin = imm.getKnowledge( "packetSpoofWin" )

        logItems = ["PacketAllocatePacket", "()"]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        packetSpoofWin.add( regs['EIP'], logItems )

class PacketInitPacket(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        packetSpoofWin = imm.getKnowledge( "packetSpoofWin" )

        logItems = ["PacketInitPacket", "("]
        packetSpoofWin.add( regs['EIP'], logItems )

        lpPacket = imm.readLong( regs['ESP'], 0x4 )
        logItems = [ "", "lpPacket = \"0x%08x\"" % (lpPacket)]
        packetSpoofWin.add( regs['EIP'], logItems )

        Buffer = imm.readLong( regs['ESP'], 0x8 )
        logItems = [ "", "Buffer = \"0x%08x\"" % (Buffer)]
        packetSpoofWin.add( regs['EIP'], logItems )

        Length = imm.readLong( regs['ESP'], 0xC )
        logItems = [ "", "Length = \"0x%08x\"" % (Length)]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        packetSpoofWin.add( regs['EIP'], logItems )

class PacketSendPacket(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        packetSpoofWin = imm.getKnowledge( "packetSpoofWin" )

        logItems = ["PacketSendPacket", "("]
        packetSpoofWin.add( regs['EIP'], logItems )

        AdapterObject = imm.readLong( regs['ESP'], 0x4 )
        logItems = [ "", "AdapterObject = \"0x%08x\"" % (AdapterObject)]
        packetSpoofWin.add( regs['EIP'], logItems )

        lpPacket = imm.readLong( regs['ESP'], 0x8 )
        logItems = [ "", "lpPacket = \"0x%08x\"" % (lpPacket)]
        packetSpoofWin.add( regs['EIP'], logItems )

        Sync = imm.readLong( regs['ESP'], 0xC )
        logItems = [ "", "Sync = \"0x%08x\"" % (Sync)]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        packetSpoofWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        packetSpoofWin.add( regs['EIP'], logItems )

#########################################################################
"""
httpTunneling Hooks
"""
class InternetOpenA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = ["InternetOpenA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpszAgent = imm.readString( ptr )
        logItems = [ "", "lpszAgent = '%s'" % (lpszAgent) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwAccessType = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwAccessType = \"0x%08x\"" % (dwAccessType) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpszProxyName = imm.readString( ptr )
        logItems = [ "", "lpszProxyName = '%s'" % (lpszProxyName) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpszProxyBypass = imm.readString( ptr )
        logItems = [ "", "lpszProxyBypass = '%s'" % (lpszProxyBypass) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class InternetOpenUrlA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = ["InternetOpenUrlA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hInternet = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hInternet = \"0x%08x\"" % (hInternet) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpszUrl = imm.readString( ptr )
        logItems = [ "", "lpszUrl = '%s'" % (lpszUrl) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpszHeaders = imm.readString( ptr )
        logItems = [ "", "lpszHeaders = '%s'" % (lpszHeaders) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwHeadersLength = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwHeadersLength = \"0x%08x\"" % (dwHeadersLength) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwContext = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwContext = \"0x%08x\"" % (dwContext) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class InternetConnectA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = [ "InternetConnectA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hInternet = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hInternet = \"0x%08x\"" % (hInternet) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpszServerName = imm.readString( ptr )
        logItems = [ "", "lpszServerName = '%s'" % (lpszServerName) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        nServerPort = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "nServerPort = \"0x%08x\"" % (nServerPort) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpszUserName = imm.readString( ptr )
        logItems = [ "", "lpszUserName = '%s'" % (lpszUserName) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        lpszPassword = imm.readString( ptr )
        logItems = [ "", "lpszPassword = '%s'" % (lpszPassword) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwService = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwService = \"0x%08x\"" % (dwService) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwContext = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "dwContext = \"0x%08x\"" % (dwContext) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class HttpOpenRequestA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = ["HttpOpenRequestA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hConnect = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hInternet = \"0x%08x\"" % (hConnect) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpszVerb = imm.readString( ptr )
        logItems = [ "", "lpszVerb = '%s'" % (lpszVerb) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpszObjectName = imm.readString( ptr )
        logItems = [ "", "lpszObjectName = '%s'" % (lpszObjectName) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpszVersion = imm.readString( ptr )
        logItems = [ "", "lpszVersion = '%s'" % (lpszVersion) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        lpszReferer = imm.readString( ptr )
        logItems = [ "", "lpszReferer = '%s'" % (lpszReferer) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x18 )
        lplpszAcceptTypes = imm.readString( ptr )
        logItems = [ "", "lplpszAcceptTypes = '%s'" % (lplpszAcceptTypes) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwContext = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "dwContext = \"0x%08x\"" % (dwContext) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class HttpAddRequestHeadersA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = ["HttpAddRequestHeadersA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hConnect = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hConnect = \"0x%08x\"" % (hConnect) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpszHeaders = imm.readString( ptr )
        logItems = [ "", "lpszHeaders = '%s'" % (lpszHeaders) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwHeadersLength = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwHeadersLength = \"0x%08x\"" % (dwHeadersLength) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwModifiers  = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwModifiers = \"0x%08x\"" % (dwModifiers) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class InternetReadFile(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = [ "InternetReadFile", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwNumberOfBytesToRead = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwNumberOfBytesToRead = \"0x%08x\"" % (dwNumberOfBytesToRead) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        lpdwNumberOfBytesRead = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpdwNumberOfBytesRead = \"0x%08x\"" % (lpdwNumberOfBytesRead) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class InternetReadFileExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = [ "InternetReadFileExA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        hFile = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hFile = \"0x%08x\"" % (hFile) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        lpBuffersOut = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBuffersOut = \"0x%08x\"" % (lpBuffersOut) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwContext = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwContext = \"0x%08x\"" % (dwContext) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

class URLDownloadToFileA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        httpTunnelWin = imm.getKnowledge( "httpTunnelWin" )

        logItems = ["URLDownloadToFileA", "(" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        pCaller = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "pCaller = \"0x%08x\"" % (pCaller) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        szURL = imm.readString( ptr )
        logItems = [ "", "szURL = '%s'" % (szURL) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        szFileName = imm.readString( ptr )
        logItems = [ "", "szFileName = '%s'" % (szFileName) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        dwReserved = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwReserved = \"0x%08x\"" % (dwReserved) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        lpfnCB = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpfnCB = \"0x%08x\"" % (lpfnCB) ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        httpTunnelWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        httpTunnelWin.add( regs['EIP'], logItems )

#########################################################################
"""
processInjection Hooks
"""
class VirtualAllocEx(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["VirtualAllocEx", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hProcess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hProcess = \"0x%08x\"" % (hProcess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpAddress = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpAddress = \"0x%08x\"" % (lpAddress) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwSize = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwSize = \"0x%08x\"" % (dwSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        flAllocationType = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "flAllocationType = \"0x%08x\"" % (flAllocationType) ]
        processInjectionWin.add( regs['EIP'], logItems )

        flProtect = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "flProtect = \"0x%08x\"" % (flProtect) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        processInjectionWin.add( regs['EIP'], logItems )

class CreateRemoteThread(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["CreateRemoteThread", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hProcess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hProcess = \"0x%08x\"" % (hProcess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpThreadAttributes = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpThreadAttributes = \"0x%08x\"" % (lpThreadAttributes) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwStackSize = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", " dwStackSize = \"0x%08x\"" % (dwStackSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpStartAddress = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpStartAddress = \"0x%08x\"" % (lpStartAddress) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpParameter = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpParameter = \"0x%08x\"" % (lpParameter) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwCreationFlags = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwCreationFlags = \"0x%08x\"" % (dwCreationFlags) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpThreadId = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "lpThreadId = \"0x%08x\"" % (lpThreadId) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class OpenProcess(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["OpenProcess", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwDesiredAccess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "dwDesiredAccess = \"0x%08x\"" % (dwDesiredAccess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        bInheritHandle = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "bInheritHandle = \"0x%08x\"" % (bInheritHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwProcessId = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwProcessId = \"0x%08x\"" % (dwProcessId) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class ReadProcessMemory(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["ReadProcessMemory", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hProcess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hProcess = \"0x%08x\"" % (hProcess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpBaseAddress = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBaseAddress = \"0x%08x\"" % (lpBaseAddress) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        processInjectionWin.add( regs['EIP'], logItems )

        nSize = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "nSize = \"0x%08x\"" % (nSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpNumberOfBytesRead = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpNumberOfBytesRead = \"0x%08x\"" % (lpNumberOfBytesRead) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class WriteProcessMemory(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["WriteProcessMemory", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hProcess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hProcess = \"0x%08x\"" % (hProcess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpBaseAddress = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpBaseAddress = \"0x%08x\"" % (lpBaseAddress) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpBuffer = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpBuffer = \"0x%08x\"" % (lpBuffer) ]
        processInjectionWin.add( regs['EIP'], logItems )

        nSize = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "nSize = \"0x%08x\"" % (nSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpNumberOfBytesWritten = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpNumberOfBytesWritten = \"0x%08x\"" % (lpNumberOfBytesWritten) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class CreateToolhelp32Snapshot(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["CreateToolhelp32Snapshot", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwFlags = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "dwFlags = \"0x%08x\"" % (dwFlags) ]
        processInjectionWin.add( regs['EIP'], logItems )

        th32ProcessID = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "th32ProcessID = \"0x%08x\"" % (th32ProcessID) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class Process32First(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["Process32First", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hSnapshot = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hSnapshot = \"0x%08x\"" % (hSnapshot) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lppe = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lppe = \"0x%08x\"" % (lppe) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class Process32Next(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["Process32Next", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hSnapshot = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hSnapshot = \"0x%08x\"" % (hSnapshot) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lppe = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lppe = \"0x%08x\"" % (lppe) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class GetWindowThreadProcessId(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["GetWindowThreadProcessId", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        hWind = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hWind = \"0x%08x\"" % (hWind) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpdwProcessId = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpdwProcessId = \"0x%08x\"" % (lpdwProcessId) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class SetWindowsHookExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = ["SetWindowsHookExA", "(" ]
        processInjectionWin.add( regs['EIP'], logItems )

        idHook = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "idHook = \"0x%08x\"" % (idHook) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpfn = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpfn = \"0x%08x\"" % (lpfn) ]
        processInjectionWin.add( regs['EIP'], logItems )

        hMod = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "hMod = \"0x%08x\"" % (hMod) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwThreadId = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwThreadId = \"0x%08x\"" % (dwThreadId) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class SetThreadContext(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin")

        logItems = ["SetThreadContext", "("]
        processInjectionWin.add( regs['EIP'], logItems)

        hThread = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hThread = \"0x%08x\"" % (hThread) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpContext = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpContext = \"0x%08x\"" % (lpContext) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class GetThreadContext(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin")

        logItems = ["GetThreadContext", "("]
        processInjectionWin.add( regs['EIP'], logItems)

        hThread = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hThread = \"0x%08x\"" % (hThread) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpContext = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpContext = \"0x%08x\"" % (lpContext) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class SetThreadExecutionState(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "SetThreadExecutionState", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        esFlags = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "esFlags = \"0x%08x\"" % (esFlags) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class OpenThread(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "OpenThread", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        dwDesiredAccess = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "dwDesiredAccess = \"0x%08x\"" % (dwDesiredAccess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        bInheritHandle = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "bInheritHandle = \"0x%08x\"" % (bInheritHandle)]
        processInjectionWin.add( regs['EIP'], logItems )

        dwThreadId = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "dwThreadId = \"0x%08x\"" % (dwThreadId)]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class SuspendThread(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "SuspendThread", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        hThread = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hThread = \"0x%08x\"" % (hThread) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class ResumeThread(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "SuspendThread", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        hThread = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hThread = \"0x%08x\"" % (hThread) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

#this creates a lot of noise and is currently not being called from processInjectionHooks()
class ZwMapViewOfSection(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "ZwMapViewOfSection", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        SectionHandle = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "SectionHandle = \"0x%08x\"" % (SectionHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        ProcessHandle = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "ProcessHandle = \"0x%08x\"" % (ProcessHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        BaseAddress = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "BaseAddress = \"0x%08x\"" % (BaseAddress) ]
        processInjectionWin.add( regs['EIP'], logItems )

        ZeroBits = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "ZeroBits = \"0x%08x\"" % (ZeroBits) ]
        processInjectionWin.add( regs['EIP'], logItems )

        CommitSize = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "CommitSize = \"0x%08x\"" % (CommitSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        SectionOffset = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "SectionOffset = \"0x%08x\"" % (SectionOffset) ]
        processInjectionWin.add( regs['EIP'], logItems )

        ViewSize = imm.readLong( regs['ESP'] + 0x1c )
        logItems = [ "", "ViewSize = \"0x%08x\"" % (ViewSize) ]
        processInjectionWin.add( regs['EIP'], logItems )

        InheritDisposition = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "InheritDisposition = \"0x%08x\"" % (InheritDisposition) ]
        processInjectionWin.add( regs['EIP'], logItems )

        AllocationType = imm.readLong( regs['ESP'] + 0x24 )
        logItems = [ "", "AllocationType = \"0x%08x\"" % (AllocationType) ]
        processInjectionWin.add( regs['EIP'], logItems )

        Protect = imm.readLong( regs['ESP'] + 0x28 )
        logItems = [ "", "Protect = \"0x%08x\"" % (Protect) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class QueueUserAPC(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "QueueUserAPC", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        pfnAPC = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "pfnAPC = \"0x%08x\"" % (pfnAPC) ]
        processInjectionWin.add( regs['EIP'], logItems )

        hThread = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "hThread = \"0x%08x\"" % (hThread) ]
        processInjectionWin.add( regs['EIP'], logItems )

        dwData = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "dwData = \"0x%08x\"" % (dwData) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class OpenProcessToken(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "OpenProcessToken", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        ProcessHandle = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "ProcessHandle = \"0x%08x\"" % (ProcessHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        DesiredAccess = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "DesiredAccess = \"0x%08x\"" % (DesiredAccess) ]
        processInjectionWin.add( regs['EIP'], logItems )

        TokenHandle = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "TokenHandle = \"0x%08x\"" % (TokenHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class LookupPrivilegeValueA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "LookupPrivilegeValueA", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpSystemName = imm.readString( ptr )
        logItems = [ "", "lpSystemName = \"%s\"" % (lpSystemName) ]
        processInjectionWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpName = imm.readString( ptr )
        logItems = [ "", "lpName = \"%s\"" % (lpName) ]
        processInjectionWin.add( regs['EIP'], logItems )

        lpLuid = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "lpLuid = \"0x%08x\"" % (lpLuid) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

class AdjustTokenPrivileges(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self, regs):
        imm = immlib.Debugger()
        processInjectionWin = imm.getKnowledge( "processInjectionWin" )

        logItems = [ "AdjustTokenPrivileges", "("]
        processInjectionWin.add( regs['EIP'], logItems )

        TokenHandle = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "TokenHandle = \"0x%08x\"" % (TokenHandle) ]
        processInjectionWin.add( regs['EIP'], logItems )

        DisableAllPrivileges = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "DisableAllPrivileges = \"0x%08x\"" % (DisableAllPrivileges) ]
        processInjectionWin.add( regs['EIP'], logItems )

        NewState = imm.readLong( regs['ESP'] + 0xc )
        logItems = [ "", "NewState = \"0x%08x\"" % (NewState) ]
        processInjectionWin.add( regs['EIP'], logItems )

        BufferLength = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "BufferLength = \"0x%08x\"" % (BufferLength) ]
        processInjectionWin.add( regs['EIP'], logItems )

        PreviousState = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "PreviousState = \"0x%08x\"" % (PreviousState) ]
        processInjectionWin.add( regs['EIP'], logItems )

        ReturnLength = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "ReturnLength = \"0x%08x\"" % (ReturnLength) ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processInjectionWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processInjectionWin.add( regs['EIP'], logItems )

#########################################################################
"""
processCreation Hooks
"""
class CreateProcessA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["CreateProcessA", "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpApplicationName = imm.readString( ptr )
        logItems = [ "", "lpApplicationName = '%s'" % (lpApplicationName) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpCommandLine = imm.readString( ptr )
        logItems = [ "", "lpCommandLine = '%s'" % (lpCommandLine) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessAttributes = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpProcessAttributes = \"0x%08x\"" % (lpProcessAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpThreadAttributes = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpThreadAttributes = \"0x%08x\"" % (lpThreadAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        bInheritHandles = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "bInheritHandles = \"0x%08x\"" % (bInheritHandles) ]
        processCreationWin.add( regs['EIP'], logItems )

        dwCreationFlags = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "dwCreationFlags = \"0x%08x\"" % (dwCreationFlags) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpEnviornment = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "lpEnviornment = \"0x%08x\"" % (lpEnviornment) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x20 )
        lpCurrentDirectory = imm.readString( ptr )
        logItems = [ "", "lpCurrentDirectory = '%s'" % (lpCurrentDirectory) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpStartupInfo = imm.readLong( regs['ESP'] + 0x24 )
        logItems = [ "", "lpStartupInfo = \"0x%08x\"" % (lpStartupInfo) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessInformation = imm.readLong( regs['ESP'] + 0x28 )
        logItems = [ "", "lpProcessInformation = \"0x%08x\"" % (lpProcessInformation) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

class WinExec(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["WinExec", "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpCmdLine = imm.readString( ptr )
        logItems = [ "", "lpCmdLine = '%s'" % (lpCmdLine) ]
        processCreationWin.add( regs['EIP'], logItems )

        uCmdShow = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "uCmdShow = \"0x%08x\"" % (uCmdShow) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

class CreateProcessAsUserA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["CreateProcessAsUserA",  "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        hToken = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hToken = \"0x%08x\"" % (hToken) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpApplicationName = imm.readString( ptr )
        logItems = [ "", "lpApplicationName = '%s'" % (lpApplicationName) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpCommandLine = imm.readString( ptr )
        logItems = [ "", "lpCommandLine = '%s'" % (lpCommandLine) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessAttributes = imm.readLong( regs['ESP'] + 0x10)
        logItems = [ "", "lpProcessAttributes = \"0x%08x\"" % (lpProcessAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpThreadAttributes = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpThreadAttributes = \"0x%08x\"" % (lpThreadAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        bInheritHandles = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "bInheritHandles = \"0x%08x\"" % (bInheritHandles) ]
        processCreationWin.add( regs['EIP'], logItems )

        dwCreationFlags = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "dwCreationFlags = \"0x%08x\"" % (dwCreationFlags) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpEnviornment = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "lpEnviornment = \"0x%08x\"" % (lpEnviornment) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x24 )
        lpCurrentDirectory = imm.readString( ptr )
        logItems = [ "", "lpCurrentDirectory = '%s'" % (lpCurrentDirectory) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpStartupInfo = imm.readLong( regs['ESP'] + 0x28 )
        logItems = [ "", "lpStartupInfo = \"0x%08x\"" % (lpStartupInfo) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessInformation = imm.readLong( regs['ESP'] + 0x2C )
        logItems = [ "", "lpProcessInformation = \"0x%08x\"" % (lpProcessInformation) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ""]
        processCreationWin.add( regs['EIP'], logItems )


class CreateProcessWithLogonW(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["CreateProcessWithLogonW", "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpUserNameW = imm.readWString( ptr )
        lpUserName = getASCII( lpUserNameW )

        logItems = [ "", "lpUserName = '%s'" % (lpUserName) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpDomainW = imm.readWString( ptr )
        lpDomain = getASCII( lpDomainW )

        logItems = [ "", "lpDomain = '%s'" % (lpDomain) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpPasswordW = imm.readWString( ptr )
        lpPassword = getASCII( lpPasswordW )

        logItems = [ "", "lpPassword = '%s'" % (lpPassword) ]
        processCreationWin.add( regs['EIP'], logItems )

        dwLogonFlags = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwLogonFlags = \"0x%08x\"" % (dwLogonFlags) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        lpApplicationNameW = imm.readWString( ptr )
        lpApplicationName = getASCII( lpApplicationNameW )

        logItems = [ "", "lpApplicationName = '%s'" % (lpApplicationName) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x18 )
        lpCommandLineW = imm.readWString( ptr )
        lpCommandLine = getASCII( lpCommandLineW )

        logItems = [ "", "lpCommandLine = '%s'" % (lpCommandLine) ]
        processCreationWin.add( regs['EIP'], logItems )

        dwCreationFlags = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "dwCreationFlags = \"0x%08x\"" % (dwCreationFlags) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpEnviornment = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "lpEnviornment = \"0x%08x\"" % (lpEnviornment) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x24 )
        lpCurrentDirectoryW = imm.readWString( ptr )
        lpCurrentDirectory = getASCII(lpCurrentDirectoryW)

        logItems = [ "", "lpCurrentDirectory = '%s'" % (lpCurrentDirectory) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpStartupInfo = imm.readLong( regs['ESP'] + 0x28 )
        logItems = [ "", "lpStartupInfo = \"0x%08x\"" % (lpStartupInfo) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessInfo = imm.readLong( regs['ESP'] + 0x2C )
        logItems = [ "", "lpProcessInfo = \"0x%08x\"" % (lpProcessInfo) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

class ShellExecuteA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["ShellExecuteA", "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        hWind = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hWind = \"0x%08x\"" % (hWind) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpOperation = imm.readString( ptr )
        logItems = [ "", "lpOperation = '%s'" % (lpOperation) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpFile = imm.readString( ptr )
        logItems = [ "", "lpFile = '%s'" % (lpFile) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x10 )
        lpParameters = imm.readString( ptr )
        logItems = [ "", "lpParameters = '%s'" % (lpParameters) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        lpDirectory = imm.readString( ptr )
        logItems = [ "", "lpDirectory = '%s'" % (lpDirectory) ]
        processCreationWin.add( regs['EIP'], logItems )

        nShowCmd = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "nShowCmd = \"0x%08x\"" % (nShowCmd) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

class CreateProcessInternalW(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["CreateProcessInternalW", "(" ]
        processCreationWin.add( regs['EIP'], logItems )

        hToken = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hToken = \"0x%08x\"" % (hToken) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpApplicationNameW = imm.readWString( ptr )
        lpApplicationName = getASCII(lpApplicationNameW)

        logItems = [ "", "lpApplicationName = '%s'" % (lpApplicationName) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xc )
        lpCommandLineW = imm.readWString( ptr )
        lpCommandLine = getASCII(lpCommandLineW)

        logItems = [ "", "lpCommandLine = \"%s\"" % (lpCommandLine) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessAttributes = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpProcessAttributes = \"0x%08x\"" % (lpProcessAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpThreadAttributes = imm.readLong( regs['ESP'] + 0x14 )
        logItems = [ "", "lpThreadAttributes = \"0x%08x\"" % (lpThreadAttributes) ]
        processCreationWin.add( regs['EIP'], logItems )

        bInheritHandles = imm.readLong( regs['ESP'] + 0x18 )
        logItems = [ "", "bInheritHandles = \"0x%08x\"" % (bInheritHandles) ]
        processCreationWin.add( regs['EIP'], logItems )

        dwCreationFlags = imm.readLong( regs['ESP'] + 0x1C )
        logItems = [ "", "dwCreationFlags = \"0x%08x\"" % (dwCreationFlags) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpEnvironment = imm.readLong( regs['ESP'] + 0x20 )
        logItems = [ "", "lpEnvironment = \"0x%08x\"" % (lpEnvironment) ]
        processCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x24 )
        lpCurrentDirectoryW = imm.readWString( ptr )
        lpCurrentDirectory = getASCII(lpCurrentDirectoryW)

        logItems = [ "", "lpCurrentDirectory = \"%s\"" % (lpCurrentDirectory) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpStartupInfo = imm.readLong( regs['ESP'] + 0x28 )
        logItems = [ "", "lpStartupInfo = \"0x%08x\"" % (lpStartupInfo) ]
        processCreationWin.add( regs['EIP'], logItems )

        lpProcessInformation = imm.readLong( regs['ESP'] + 0x2c )
        logItems = [ "", "lpProcessInformation = \"0x%08x\"" % (lpProcessInformation) ]
        processCreationWin.add( regs['EIP'], logItems )

        hNewToken = imm.readLong( regs['ESP'] + 0x30 )
        logItems = [ "", "hNewToken = \"0x%08x\"" % (hNewToken) ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

class CreateProcessAsUserSecure(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        processCreationWin = imm.getKnowledge( "processCreationWin" )

        logItems = ["CreateProcessAsUserSecure", "Incomplete" ]
        processCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        processCreationWin.add( regs['EIP'], logItems )

#########################################################################
"""
serviceCreation Hooks
"""
class OpenSCManagerA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["OpenSCManagerA", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        lpMachineName = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "lpMachineName = \"0x%08x\"" % (lpMachineName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        lpDatabaseName = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "lpDatabaseName = \"0x%08x\"" % (lpDatabaseName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwDesiredAccess = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwDesiredAccess = \"0x%08x\"" % (dwDesiredAccess) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class StartServiceA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["StartServiceA", "(" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        hService = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hService = \"0x%08x\"" % (hService) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwNumServiceArgs = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwNumServiceArgs = \"0x%08x\"" % (dwNumServiceArgs) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        lpServiceArgVectors = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpServiceArgVectors = \"0x%08x\"" % (lpServiceArgVectors) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class ControlService(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["ControlService", "(" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        hService = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hService = \"0x%08x\"" % (hService) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwControl = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwControl = \"0x%08x\"" % (dwControl) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        lpServiceStatus = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpServiceStatus = \"0x%08x\"" % (lpServiceStatus) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class OpenServiceA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["OpenServiceA", "(" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        hSCManager = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hSCManager = \"0x%08x\"" % (hSCManager) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpServiceName = imm.readString( ptr )
        logItems = [ "", "lpServiceName = '%s'" % (lpServiceName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwDesiredAccess = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwDesiredAccess = \"0x%08x\"" % (dwDesiredAccess) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class ChangeServiceConfigA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["ChangeServiceConfigA", "(" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        hService = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hService = \"0x%08x\"" % (hService) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwServiceType = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwServiceType = \"0x%08x\"" % (dwServiceType) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwStartType = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "dwStartType = \"0x%08x\"" % (dwStartType) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwErrorControl = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "dwErrorControl = \"0x%08x\"" % (dwErrorControl) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x14 )
        lpBinaryPathName = imm.readString( ptr )
        logItems = [ "", "lpBinaryPathName = '%s'" % (lpBinaryPathName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x18 )
        lpLoadOrderGroup = imm.readString( ptr )
        logItems = [ "", "lpLoadOrderGroup = '%s'" % (lpLoadOrderGroup) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x1C )
        lpdwTagId = imm.readString( ptr )
        logItems = [ "", "lpdwTagId = '%s'" % (lpdwTagId) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x20 )
        lpDependencies = imm.readString( ptr )
        logItems = [ "", "lpDependencies = '%s'" % (lpDependencies) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x24 )
        lpServiceStartName = imm.readString( ptr )
        logItems = [ "", "lpServiceStartName = '%s'" % (lpServiceStartName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x28 )
        lpPassword = imm.readString( ptr )
        logItems = [ "", "lpPassword = '%s'" % (lpPassword) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x2C )
        lpDisplayName = imm.readString( ptr )
        logItems = [ "", "lpDisplayName = '%s'" % (lpDisplayName) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class ChangeServiceConfig2A(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["ChangeServiceConfig2A", "("]
        serviceCreationWin.add( regs['EIP'], logItems )

        hService = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hService = \"0x%08x\"" % (hService) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        dwInfoLevel = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwInfoLevel = \"0x%08x\"" % (dwInfoLevel) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        lpInfo = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "lpInfo = \"0x%08x\"" % (lpInfo) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

class DeleteService(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        serviceCreationWin = imm.getKnowledge( "serviceCreationWin" )

        logItems = ["DeleteService", "(" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        hService = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hService = \"0x%08x\"" % (hService) ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        serviceCreationWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        serviceCreationWin.add( regs['EIP'], logItems )

#########################################################################
"""
keyLoggAttempt Hooks
"""

'''
This function can also be used to perform process injection
I would rather be told about process injection then potential
keylogging
class SetWindowsHookExA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        idHook = imm.readLong( regs['ESP'] + 0x4 )
        lpfn = imm.readLong( regs['ESP'] + 0x8 )
        hMod = imm.readLong( regs['ESP'] + 0xC )
        dwThreadId = imm.readLong( regs['ESP'] + 0x10 )
        keyLoggAttemptWin = imm.getKnowledge( "keyLoggAttemptWin" )
        logItems = ["SetWindowsHookExA", "(" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", "idHook = \"0x%08x\"" % (idHook) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", "lpfn = \"0x%08x\"" % (lpfn) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", "hMod = \"0x%08x\"" % (hMod) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", "dwThreadId = \"0x%08x\"" % (dwThreadId)]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", ")" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
        logItems = [ "", "" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )
'''
class GetKeyboardState(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        keyLoggAttemptWin = imm.getKnowledge( "keyLoggAttemptWin" )

        logItems = ["GetKeyboardState", "(" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        lpKeyState = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "lpKeyState = \"0x%08x\"" % (lpKeyState) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

class GetKeyState(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        keyLoggAttemptWin = imm.getKnowledge( "keyLoggAttemptWin" )

        logItems = ["GetKeyState", "(" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        nVirtKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "nVirtKey = \"0x%08x\"" % (nVirtKey) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

class GetAsyncKeyState(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        keyLoggAttemptWin = imm.getKnowledge( "keyLoggAttemptWin" )

        logItems = ["GetAsyncKeyState", "(" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        vKey = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "vKey = \"0x%08x\"" % (vKey) ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

class GetForegroundWindow(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        keyLoggAttemptWin = imm.getKnowledge( "keyLoggAttemptWin" )

        logItems = ["GetForegroundWindow", "()"]
        keyLoggAttemptWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        keyLoggAttemptWin.add( regs['EIP'], logItems )


#########################################################################
"""
malIndicator Hooks
"""
class CreateMutexA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["CreateMutexA", "(" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        lpMutexAttributes = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "lpMutexAttributes = \"0x%08x\"" % (lpMutexAttributes) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        bInitialOwner = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "bInitialOwner = \"0x%08x\"" % (bInitialOwner) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0xC )
        lpName = imm.readString( ptr )
        logItems = [ "", "lpName = '%s'" % (lpName) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class VirtualProtect(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["VirtualProtect", "(" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        lpAddress = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "lpAddress = \"0x%08x\"" % (lpAddress) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        dwSize = imm.readLong( regs['ESP'] + 0x8 )
        logItems = [ "", "dwSize = \"0x%08x\"" % (dwSize) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        flNewProtect = imm.readLong( regs['ESP'] + 0xC )
        logItems = [ "", "flNewProtect = \"0x%08x\"" % (flNewProtect) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        lpflOldProtect = imm.readLong( regs['ESP'] + 0x10 )
        logItems = [ "", "lpflOldProtect = \"0x%08x\"" % (lpflOldProtect) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class LoadLibraryA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["LoadLibraryA", "(" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpFileName = imm.readString( ptr )
        logItems = [ "", "lpFileName = '%s'" % (lpFileName) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class GetProcAddress(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["GetProcAddress", "(" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        hModule = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "hModule = \"0x%08x\"" % (hModule) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x8 )
        lpProcName = imm.readString( ptr )

        logItems = [ "", "lpProcName = '%s'" % (lpProcName) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class GetModuleHandleA(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["GetModuleHandleA", "(" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        lpModuleName = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "lpModuleName = \"0x%08x\"" % (lpModuleName) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class ZwLoadDriver(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["ZwLoadDriver", "("]
        malIndicatorWin.add( regs['EIP'], logItems )

        ptr = imm.readLong( regs['ESP'] + 0x4 )
        DriverServiceNameW = imm.readWString( ptr )
        DriverServiceName = getASCII( DriverServiceNameW )

        logItems = [ "", "DriverServiceName = '%s'" % (DriverServiceName) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )

class ZwSetSystemInformation(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
        malIndicatorWin = imm.getKnowledge( "malIndicatorWin" )

        logItems = ["ZwSetSystemInformation", "("]
        malIndicatorWin.add( regs['EIP'], logItems )

        SystemInformationClass = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "SystemInformationClass = \"0x%08x\"" % (SystemInformationClass) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        SystemInformation = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "SystemInformation = \"0x%08x\"" % (SystemInformation) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        SystemInformationLength = imm.readLong( regs['ESP'] + 0x4 )
        logItems = [ "", "SystemInformationLength = \"0x%08x\"" % (SystemInformationLength) ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", ")" ]
        malIndicatorWin.add( regs['EIP'], logItems )

        logItems = [ "", "" ]
        malIndicatorWin.add( regs['EIP'], logItems )


class LoadLibraryRet(LogBpHook):
    def __init__(self):
        LogBpHook.__init__(self)

    def run(self,regs):
        imm = immlib.Debugger()
#TODO: think there is a bug here somewhere
        ptr = imm.readLong( regs['ESP'] + 0x4 )
        lpFileName = imm.readString( ptr )
        lpFileName = lpFileName.upper()

        if ((lpFileName.find("ADVAPI32")) > -1):
            if(imm.getKnowledge("regMonWin") == None):
                columnTitles = [ "Functions", "Args" ]
                regMonWin = imm.createWindow( "RegMon", columnTitles )
                imm.addKnowledge( "regMonWin", regMonWin, force_add=0x1)
            regMonHooks( imm )
            if ((imm.getKnowledge("processCreationWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                processCreationWin = imm.createWindow( "Process Creation", columnTitles )
                imm.addKnowledge( "processCreationWin", processCreationWin, force_add=0x1)
            processCreationHooks( imm )
            if ((imm.getKnowledge("serviceCreationWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                serviceCreationWin = imm.createWindow( "Service Creation", columnTitles )
                imm.addKnowledge( "serviceCreationWin", serviceCreationWin, force_add=0x1)
            serviceCreationHooks( imm )
            if ((imm.getKnowledge("processInjectionWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                processInjectionWin = imm.createWindow( "Process Injection", columnTitles )
                imm.addKnowledge( "processInjectionWin", processInjectionWin, force_add=0x1)
            processInjectionHooks( imm )

        if ((lpFileName.find("DNSAPI")) > -1):
            if (imm.getKnowledge("dnsRequest") == None):
                columnTitles = [ "Function", "Args" ]
                dnsRequest = imm.createWindow( "DNS Requests", columnTitles )
                imm.addKnowledge( "dnsRequest", dnsRequest, force_add=0x1 )
            dnsRequestHooks( imm )

        if ((lpFileName.find("WS2_32")) > -1):
            if ((imm.getKnowledge("sendRecvWin")) == None):
                columnTitles = [ "Send Buf", "Recv Buf" ]
                sendRecvWin = imm.createWindow( "Send / Recv", columnTitles )
                imm.addKnowledge( "sendRecvWin", sendRecvWin, force_add=0x1)
            generalSocketCommHooks( imm )
            if ((imm.getKnowledge("promiscuousModeWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                promiscuousModeWin = imm.createWindow( "Promiscuous Mode", columnTitles )
                imm.addKnowledge( "promiscuousModeWin", promiscuousModeWin, force_add=0x1)
            promiscuousModeHooks( imm )

        if ((lpFileName.find("PACKET")) > -1):
            if ((imm.getKnowledge("packetSpoofWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                packetSpoofWin = imm.createWindow( "Packet Spoofing", columnTitles )
                imm.addKnowledge( "packetSpoofWin", packetSpoofWin, force_add=0x1)
            packetSpoofHooks( imm )

        if ((lpFileName.find("WININET")) > -1):
            if ((imm.getKnowledge("httpTunnelWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                httpTunnelWin = imm.createWindow( "HTTP Tunneling", columnTitles )
                imm.addKnowledge( "httpTunnelWin", httpTunnelWin, force_add=0x1)
            httpTunnelingHooks( imm )

        if ((lpFileName.find("URLMON")) > -1):
            if ((imm.getKnowledge("httpTunnelWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                httpTunnelWin = imm.createWindow( "HTTP Tunneling", columnTitles )
                imm.addKnowledge( "httpTunnelWin", httpTunnelWin, force_add=0x1)
            httpTunnelingHooks( imm )

        if ((lpFileName.find("USER32")) > -1):
            if ((imm.getKnowledge("processInjectionWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                processInjectionWin = imm.createWindow( "Process Injection", columnTitles )
                imm.addKnowledge( "processInjectionWin", processInjectionWin, force_add=0x1)
            processInjectionHooks( imm )
            if ((imm.getKnowledge("keyLoggAttemptWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                keyLoggAttemptWin = imm.createWindow( "Keylogg Attempt", columnTitles )
                imm.addKnowledge( "keyLoggAttemptWin", keyLoggAttemptWin, force_add=0x1)
            keyLoggAttemptHooks( imm )

        if ((lpFileName.find("SHELL32")) > -1):
            if ((imm.getKnowledge("processCreationWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                processCreationWin = imm.createWindow( "Process Creation", columnTitles )
                imm.addKnowledge( "processCreationWin", processCreationWin, force_add=0x1)
            processCreationHooks( imm )

        if ((lpFileName.find("KERNEL32")) > -1):
            if ((imm.getKnowledge("fileMonWin")) == None):
                columnTitles = [ "Function", "Args" ]
                fileMonWin = imm.createWindow( "FileMon", columnTitles )
                imm.addKnowledge( "fileMonWin", fileMonWin, force_add = 0x1)
            fileMonHooks( imm )
            if ((imm.getKnowledge("processInjectionWin")) == None):
                columnTitles = [ "Function", "Args" ]
                processInjectionWin = imm.createWindow( "Process Injection", columnTitles )
                imm.addKnowledge( "processInjectionWin", processInjectionWin, force_add=0x1)
            processInjectionHooks( imm )
            if ((imm.getKnowledge("processCreationWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                processCreationWin = imm.createWindow( "Process Creation", columnTitles )
                imm.addKnowledge( "processCreationWin", processCreationWin, force_add=0x1)
            processCreationHooks( imm )

        if ((lpFileName.find("NTDLL")) > -1):
            if ((imm.getKnowledge("processInjectionWin")) == None):
                columnTitles = [ "Function", "Args" ]
                processInjectionWin = imm.createWindow( "Process Injection", columnTitles )
                imm.addKnowledge( "processInjectionWin", processInjectionWin, force_add=0x1)
            processInjectionHooks( imm )
            if ((imm.getKnowledge("malIndicatorWin")) == None):
                columnTitles = [ "Functions", "Args" ]
                malIndicatorWin = imm.createWindow( "Common Malware Methods", columnTitles )
                imm.addKnowledge( "malIndicatorWin", malIndicatorWin, force_add=0x1)
            malIndicatorHooks( imm )

        if ((imm.getKnowledge("breakOnExecutionRedirection")) != None):
            setBreakOnExecutionRedirection( imm )

#########################################################################
'''
This function is called from main and it creates
the log window and sets the hooks associated with
Registry Manipulation
'''
def regMon():
    imm = immlib.Debugger()
    #Make the Window
    columnTitles = ["Function","Args"]
    regMonWin = imm.createWindow("RegMon", columnTitles )
    imm.addKnowledge("regMonWin", regMonWin, force_add = 0x1)
    #Check to see if dll is loaded, lazy should fix later
    if ((imm.getAddress("Advapi32.RegOpenKeyExA")) == -1):
        logItems = ["","advapi.dll is not loaded, the hooks will not be set"]
        regMonWin.add( -1, logItems )
    regMonHooks( imm )
    imm.log("Registry Monitor Hooking Complete")

########################################################################
'''
This function resolves the addresses for each
function associated with registry manipulation
and sets the hooks
'''
def regMonHooks( imm ):
    hook = RegOpenKeyExA()
    if ((imm.getAddress("Advapi32.RegOpenKeyExA")) != -1):
        hook.add("RegOpenKeyExA", imm.getAddress("Advapi32.RegOpenKeyExA"))
        imm.log("regMonHooks: Advapi32.RegOpenKeyExA set")
    else:
        imm.log("regMonHooks: Advapi32.RegOpenKeyExA not set")

    hook = RegCreateKeyExA()
    if ((imm.getAddress("Advapi32.RegCreateKeyExA")) != -1):
        hook.add("RegCreateKeyExA", imm.getAddress("Advapi32.RegCreateKeyExA"))
        imm.log("regMonHooks: Advapi32.RegCreateKeyExA set")
    else:
        imm.log("regMonHooks: Advapi32.RegCreateKeyExA not set")

    hook = RegQueryValueExA()
    if ((imm.getAddress("Advapi32.RegQueryValueExA")) != -1):
        hook.add("RegQueryValueExA", imm.getAddress("Advapi32.RegQueryValueExA"))
        imm.log("regMonHooks: Advapi32.RegQueryValueExA set")
    else:
        imm.log("regMonHooks: Advapi32.RegQueryValueExA not set")

    hook = RegSetValueExA()
    if ((imm.getAddress("Advapi32.RegSetValueExA")) != -1):
        hook.add("RegSetValueExA", imm.getAddress("Advapi32.RegSetValueExA"))
        imm.log("regMonHooks: Advapi32.RegSetValueExA set")
    else:
        imm.log("regMonHooks: Advapi32.RegSetValueExA not set")

    hook = RegCloseKey()
    if ((imm.getAddress("Advapi32.RegCloseKey")) != -1):
        hook.add("RegCloseKey", imm.getAddress("Advapi32.RegCloseKey"))
        imm.log("regMonHooks: Advapi32.RegCloseKey set")
    else:
        imm.log("regMonHooks: Advapi32.RegCloseKey not set")

    hook = RegConnectRegistryA()
    if ((imm.getAddress("Advapi32.RegConnectRegistryA")) != -1):
        hook.add("RegConnectRegistryA", imm.getAddress("Advapi32.RegConnectRegistryA"))
        imm.log("regMonHooks: Advapi32.RegConnectRegistryA set")
    else:
        imm.log("regMonHooks: Advapi32.RegConnectRegistryA not set")

#########################################################################
'''
This function is called from main and it creates
the log window and sets hooks associated with
file IO
'''
def fileMon():
    imm = immlib.Debugger()
    #Make the Window
    columnTitles = [ "Function", "Args" ]
    fileMonWin = imm.createWindow( "FileMon", columnTitles )
    imm.addKnowledge( "fileMonWin", fileMonWin, force_add=0x1)
    #Check to see if the dll is loaded, lazy should fix later
    if ((imm.getAddress("Kernel32.CreateFileA"))== -1):
        logItems = ["", "kernel32.dll is not loaded, the hooks will not be set"]
        fileMonWin.add( -1, logItems )
    fileMonHooks( imm )
    imm.log("File Monitor Hooking Complete")

#########################################################################
'''
This function resolves address for each
function associated with file IO and sets
the hooks
'''
def fileMonHooks( imm ):
    hook = CreateFileA()
    if ((imm.getAddress("Kernel32.CreateFileA")) != -1):
        hook.add("CreateFileA", imm.getAddress("kernel32.CreateFileA"))
        imm.log("fileMonHooks: kernel32.CreateFileA set")
    else:
        imm.log("fileMonHooks: kernel32.CreateFileA not set")

    hook = ReadFile()
    if ((imm.getAddress("Kernel32.ReadFile")) != -1):
        hook.add("ReadFile", imm.getAddress("kernel32.ReadFile"))
        imm.log("fileMonHooks: kernel32.ReadFile set")
    else:
        imm.log("fileMonHooks: kernel32.ReadFile not set")

    hook = ReadFileEx()
    if ((imm.getAddress("Kernel32.ReadFileEx")) != -1):
        hook.add("ReadFileEx", imm.getAddress("kernel32.ReadFileEx"))
        imm.log("fileMonHooks: kernel32.ReadFileEx set")
    else:
        imm.log("fileMonHooks: kernel32.ReadFileEx not set")

    hook = WriteFile()
    if ((imm.getAddress("Kernel32.WriteFile")) != -1):
        hook.add("WriteFile", imm.getAddress("kernel32.WriteFile"))
        imm.log("fileMonHooks: kernel32.WriteFile set")
    else:
        imm.log("fileMonHooks: kernel32.WriteFile not set")

    hook = WriteFileEx()
    if ((imm.getAddress("Kernel32.WriteFileEx")) != -1):
        hook.add("WriteFileEx", imm.getAddress("kernel32.WriteFileEx"))
        imm.log("fileMonHooks: kernel32.WriteFileEx set")
    else:
        imm.log("fileMonHooks: kernel32.WriteFileEx not set")

    hook = DeleteFileA()
    if ((imm.getAddress("Kernel32.DeleteFileA")) != -1):
        hook.add("DeleteFileA", imm.getAddress("kernel32.DeleteFileA"))
        imm.log("fileMonHooks: kernel32.DeleseFileA set")
    else:
        imm.log("fileMonHooks: kernel32.DeleseFileA not set")

    hook = MoveFileEx()
    if ((imm.getAddress("Kernel32.MoveFileExA")) != -1):
        hook.add("MoveFileEx", imm.getAddress("kernel32.MoveFileExA"))
        imm.log("fileMonHooks: kernel32.MoveFileExA set")
    else:
        imm.log("fileMonHooks: kernel32.MoveFileExA not set")

#########################################################################
'''
This function is called from main and it creates
the log window and sets hooks associated with
DNS requests
'''
def dnsRequest():
    imm = immlib.Debugger()
    #Make the Window
    columnTitles = [ "Function", "Args" ]
    dnsRequest = imm.createWindow( "DNS Requests", columnTitles )
    imm.addKnowledge( "dnsRequest", dnsRequest, force_add=0x1 )
    #Check to see if the dll is loaded, lazy should fix later
    if ((imm.getAddress("dnsapi.DnsQuery_A")) == -1):
        logItems = ["","dnsapi.dll is not loaded, the hooks will not be set"]
        dnsRequest.add( -1, logItems )
    #Set the Hooks
    dnsRequestHooks( imm )
    imm.log("DNS Request Monitor Hooking Complete")

########################################################################
'''
This function resolves address for each function
associated with DNS requests and sets the hooks
'''
def dnsRequestHooks( imm ):
    hook = DnsQuery_A()
    if ((imm.getAddress("dnsapi.DnsQuery_A")) != -1):
        hook.add("DnsQuery_A", imm.getAddress("dnsapi.DnsQuery_A"))
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_A set")
    else:
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_A not set")

    hook = DnsQuery_W()
    if ((imm.getAddress("dnsapi.DnsQuery_W")) != -1):
        hook.add("DnsQuery_W", imm.getAddress("dnsapi.DnsQuery_W"))
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_W set")
    else:
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_W not set")

    hook = DnsQuery_UTF8()
    if ((imm.getAddress("dnsapi.DnsQuery_UTF8")) != -1):
        hook.add("DnsQuery_UTF8", imm.getAddress("dnsapi.DnsQuery_UTF8"))
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_UTF8 set")
    else:
        imm.log("dnsRequestHooks: dnsapi.DnsQuery_UTF8 not set")

#########################################################################
'''
This function is called from main and
it creates the log window and sets hooks
associated with general socket communication
'''
def generalSocketComm():
    imm = immlib.Debugger()
    #Make the Send/Recv Window
    columnTitles = [ "Send Buf", "Recv Buf" ]
    sendRecvWin = imm.createWindow( "Send / Recv", columnTitles )
    imm.addKnowledge( "sendRecvWin", sendRecvWin, force_add=0x1)
    #Check to see if the dll is loaded, lazy should fix later
    if ((imm.getAddress("WS2_32.send")) == -1):
        logItems = ["","WS2_32.dll is not loaded, the hooks will not be set"]
        sendRecvWin.add( -1, logItems )
    #Set the hooks
    generalSocketCommHooks( imm )
    imm.log("General Socket Communication Hooking Complete")

########################################################################
'''
This function resolves the addresses for
each function associated with general
socket communication and sets the hooks
'''
def generalSocketCommHooks( imm ):
    hook = WSAStartup()
    if ((imm.getAddress("WS2_32.WSAStartup")) != -1):
        hook.add("WSAStartup", imm.getAddress("WS2_32.WSAStartup"))
        imm.log("generalSocketCommHooks: WS2_32.WSAStartup set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.WSAStartup not set")

    hook = listen()
    if ((imm.getAddress("WS2_32.listen")) != -1):
        hook.add("listen", imm.getAddress("WS2_32.listen"))
        imm.log("generalSocketCommHooks: WS2_32.listen set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.listen not set")

    hook = connect()
    if ((imm.getAddress("WS2_32.connect")) != -1):
        hook.add("connect", imm.getAddress("WS2_32.connect"))
        imm.log("generalSocketCommHooks: WS2_32.connect set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.connect not set")

    hook = accept()
    if ((imm.getAddress("WS2_32.accept")) != -1):
        hook.add("accept", imm.getAddress("WS2_32.accept"))
        imm.log("generalSocketCommHooks: WS2_32.accept set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.accept not set")

    hook = send()
    if ((imm.getAddress("WS2_32.send")) != -1):
        hook.add("send", imm.getAddress("WS2_32.send"))
        imm.log("generalSocketCommHooks: WS2_32.send set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.send not set")

    hook = recv()
    if ((imm.getAddress("WS2_32.recv")) != -1):
        hook.add("recv", imm.getAddress("WS2_32.recv"))
        imm.log("generalSocketCommHooks: WS2_32.recv set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.recv not set")

    hook = WSASend()
    if ((imm.getAddress("WS2_32.WSASend")) != -1):
        hook.add("WSASend", imm.getAddress("WS2_32.WSASend"))
        imm.log("generalSocketCommHooks: WS2_32.WSASend set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.WSASend not set")

    hook = WSARecv()
    if ((imm.getAddress("WS2_32.WSARecv")) != -1):
        hook.add("WSARecv", imm.getAddress("WS2_32.WSARecv"))
        imm.log("generalSocketCommHooks: WS2_32.WSARecv set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.WSARecv not set")

    hook = recvfrom()
    if ((imm.getAddress("WS2_32.recvfrom")) != -1):
        hook.add("recvfrom", imm.getAddress("WS2_32.recvfrom"))
        imm.log("generalSocketCommHooks: WS2_32.recvfrom set")
    else:
        imm.log("generalSocketCommHooks: WS2_32.recvfrom notset")

#########################################################################
'''
This function is called from main and
it creates the log window and sets hooks
associated with placing the NIC into promiscuous
mode
'''
def promiscuousMode():
    imm = immlib.Debugger()
    #Make the promiscuousMode Window
    columnTitles = [ "Functions", "Args" ]
    promiscuousModeWin = imm.createWindow( "Promiscuous Mode", columnTitles )
    imm.addKnowledge( "promiscuousModeWin", promiscuousModeWin, force_add=0x1)
    #Check to see if the dll is loaded, lazy should fix later
    if ((imm.getAddress("WS2_32.WSASocketA")) == -1):
        logItems = ["","WS2_32.dll is not loaded, the hooks will not be set"]
        promiscuousModeWin.add( -1, logItems )
    #Set the promiscuousMode Hooks
    promiscuousModeHooks( imm )
    imm.log("Promiscuous Mode Hooking Complete")

##########################################################################
'''
This function resolves the addresses for
each function associated with placing the
NIC into promiscuous mode and sets the hooks
'''
def promiscuousModeHooks( imm ):
    hook = WSASocketA()
    if ((imm.getAddress("WS2_32.WSASocketA")) != -1):
        hook.add("WSASocketA", imm.getAddress("WS2_32.WSASocketA"))
        imm.log("promiscuousModeHooks: WS2_32.WSASocketA set")
    else:
        imm.log("promiscuousModeHooks: WS2_32.WSASocketA not set")

    hook = socket()
    if ((imm.getAddress("WS2_32.socket")) != -1):
        hook.add("socket", imm.getAddress("WS2_32.socket"))
        imm.log("promiscuousModeHooks: WS2_32.socket set")
    else:
        imm.log("promiscuousModeHooks: WS2_32.socket not set")

    hook = bind()
    if ((imm.getAddress("WS2_32.bind")) != -1):
        hook.add("bind", imm.getAddress("WS2_32.bind"))
        imm.log("promiscuousModeHooks: WS2_32.bind set")
    else:
        imm.log("promiscuousModeHooks: WS2_32.bind not set")

    hook = WSAIoctl()
    if ((imm.getAddress("WS2_32.WSAIoctl")) != -1):
        hook.add("WSAIoctl", imm.getAddress("WS2_32.WSAIoctl"))
        imm.log("promiscuousModeHooks: WS2_32.WSAIoctl set")
    else:
        imm.log("promiscuousModeHooks: WS2_32.WSAIoctl not set")

    hook = ioctlsocket()
    if ((imm.getAddress("WS2_32.ioctlsocket")) != -1):
        hook.add("ioctlsocket", imm.getAddress("WS2_32.ioctlsocket"))
        imm.log("promiscuousModeHooks: WS2_32.ioctlsocket set")
    else:
        imm.log("promiscuousModeHooks: WS2_32.ioctlsocket not set")

#########################################################################
'''
This function is called from main  and
it creates the log window and sets hooks
associated with packet spoofing
'''
def packetSpoofing():
    imm = immlib.Debugger()
    #Make the packetSpoofing Window
    columnTitles = [ "Functions", "Args" ]
    packetSpoofWin = imm.createWindow( "Packet Spoofing", columnTitles )
    imm.addKnowledge( "packetSpoofWin", packetSpoofWin, force_add=0x1)
    #Check to see if the dll is loaded, lazy should fix later
    if ((imm.getAddress("packet.PacketOpenAdapter")) == -1):
        logItems = ["","packet.dll is not loaded, the hooks will not be set"]
        packetSpoofWin.add( -1, logItems )
    #Set the packetSpoofing Hooks
    packetSpoofingHooks( imm )
    imm.log("Packet Spoof Hooking Complete")

#########################################################################
'''
This function resolves the addresses for
each function associated with packet spoofing (packet.dll from winpcap)
and sets the hooks
'''
def packetSpoofingHooks( imm ):
    hook = PacketOpenAdapter()
    if ((imm.getAddress("packet.PacketOpenAdapter")) != -1):
        hook.add("PacketOpenAdapter", imm.getAddress("packet.PacketOpenAdapter"))
        imm.log("packetSpoofingHooks: packet.PacketOpenAdapter set")
    else:
        imm.log("packetSpoofingHooks: packet.PacketOpenAdapter not set")

    hook = PacketSetBuff()
    if ((imm.getAddress("packet.PacketSetBuff")) != -1):
        hook.add("PacketSetBuff", imm.getAddress("packet.PacketSetBuff"))
        imm.log("packetSpoofingHooks: packet.PacketSetBuff set")
    else:
        imm.log("packetSpoofingHooks: packet.PacketSetBuff not set")

    hook = PacketAllocatePacket()
    if ((imm.getAddress("packet.PacketAllocatePacket")) != -1):
        hook.add("PacketAllocatePacket", imm.getAddress("packet.PacketAllocatePacket"))
        imm.log("packetSpoofingHooks: packet.PacketAllocatePacket set")
    else:
        imm.log("packetSpoofingHooks: packet.PacketAllocatePacket not set")

    hook = PacketInitPacket()
    if ((imm.getAddress("packet.PacketInitPacket")) != -1):
        hook.add("PacketInitPacket", imm.getAddress("packet.PacketInitPacket"))
        imm.log("packetSpoofingHooks: packet.PacketInitPacket set")
    else:
        imm.log("packetSpoofingHooks: packet.PacketInitPacket not set")

    hook = PacketSendPacket()
    if ((imm.getAddress("packet.PacketSendPacket")) != -1):
        hook.add("PacketSendPacket", imm.getAddress("packet.PacketSendPacket"))
        imm.log("packetSpoofingHooks: packet.PacketSendPacket set")
    else:
        imm.log("packetSpoofingHooks: packet.PacketSendPacket not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with HTTP tunneling
'''
def httpTunneling():
    imm = immlib.Debugger()
    #Make the httpTunneling Window
    columnTitles = [ "Functions", "Args" ]
    httpTunnelWin = imm.createWindow( "HTTP Tunneling", columnTitles )
    imm.addKnowledge( "httpTunnelWin", httpTunnelWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("WININET.InternetOpenA")) == -1):
        logItems = ["","WININET.dll is not loaded, the hooks will not be set"]
        httpTunnelWin.add( -1, logItems )
    if ((imm.getAddress("urlmon.URLDownloadToFileA")) == -1):
        logItems = ["","urlmon.dll is not loaded, the hooks will not be set"]
        httpTunnelWin.add( -1, logItems )
    #Set the httpTunneling Hooks
    httpTunnelingHooks( imm )
    imm.log("HTTP Tunnel Hooking Complete")

########################################################################
'''
This function resolves the addresses for
each function associated with http tunneling
and sets the hooks
'''
def httpTunnelingHooks( imm ):
    hook = InternetOpenA()
    if ((imm.getAddress("WININET.InternetOpenA")) != -1):
        hook.add("InternetOpenA", imm.getAddress("WININET.InternetOpenA"))
        imm.log("httpTunnelingHooks: WININET.InternetOpenA set")
    else:
        imm.log("httpTunnelingHooks: WININET.InternetOpenA not set")

    hook = InternetOpenUrlA()
    if ((imm.getAddress("WININET.InternetOpenUrlA")) != -1):
        hook.add("InternetOpenUrlA", imm.getAddress("WININET.InternetOpenUrlA"))
        imm.log("httpTunnelingHooks: WININET.InternetOpenUrlA set")
    else:
        imm.log("httpTunnelingHooks: WININET.InternetOpenUrlA not set")

    hook = InternetConnectA()
    if ((imm.getAddress("WININET.InternetConnectA")) != -1):
        hook.add("InternetConnectA", imm.getAddress("WININET.InternetConnectA"))
        imm.log("httpTunnelingHooks: WININET.InternetConnectA set")
    else:
        imm.log("httpTunnelingHooks: WININET.InternetConnectA not set")

    hook = HttpOpenRequestA()
    if ((imm.getAddress("WININET.HttpOpenRequestA")) != -1):
        hook.add("HttpOpenRequestA", imm.getAddress("WININET.HttpOpenRequestA"))
        imm.log("httpTunnelingHooks: WININET.HttpOpenRequestA set")
    else:
        imm.log("httpTunnelingHooks: WININET.HttpOpenRequestA not set")

    hook = HttpAddRequestHeadersA()
    if ((imm.getAddress("WININET.HttpAddRequestHeadersA")) != -1):
        hook.add("HttpAddRequestHeadersA", imm.getAddress("WININET.HttpAddRequestHeadersA"))
        imm.log("httpTunnelingHooks: WININET.HttpAddRequestHeadersA set")
    else:
        imm.log("httpTunnelingHooks: WININET.HttpAddRequestHeadersA not set")

    hook = InternetReadFile()
    if ((imm.getAddress("WININET.InternetReadFile")) != -1):
        hook.add("InternetReadFile", imm.getAddress("WININET.InternetReadFile"))
        imm.log("httpTunnelingHooks: WININET.InternetReadFile set")
    else:
        imm.log("httpTunnelingHooks: WININET.InternetReadFile not set")

    hook = InternetReadFileExA()
    if ((imm.getAddress("WININET.InternetReadFileExA")) != -1):
        hook.add("InternetReadFileExA", imm.getAddress("WININET.InternetReadFileExA"))
        imm.log("httpTunnelingHooks: WININET.InternetReadFileExA set")
    else:
        imm.log("httpTunnelingHooks: WININET.InternetReadFileExA not set")

    hook = URLDownloadToFileA()
    if ((imm.getAddress("urlmon.URLDownloadToFileA")) != -1):
        hook.add("URLDownloadToFileA", imm.getAddress("urlmon.URLDownloadToFileA"))
        imm.log("httpTunnelingHooks: urlmon.URLDownloadToFileA set")
    else:
        imm.log("httpTunnelingHooks: urlmon.URLDownloadToFileA not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with process injection
'''
def processInjection():
    imm = immlib.Debugger()
    #Make the processInjection Window
    columnTitles = [ "Functions", "Args" ]
    processInjectionWin = imm.createWindow( "Process Injection", columnTitles )
    imm.addKnowledge( "processInjectionWin", processInjectionWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("USER32.GetWindowThreadProcessId")) == -1):
        logItems = ["","USER32.dll is not loaded, some hooks will not be set"]
        processInjectionWin.add( -1, logItems )
    if ((imm.getAddress("Kernel32.CreateRemoteThread")) == -1):
        logItems = ["", "Kernel32 is not loaded, some hooks will not be set"]
        processInjectionWin.add( -1, logItems )
    #Set the processInjection Hooks
    processInjectionHooks( imm )
    imm.log("Process Injection Hooking Complete")

#########################################################################
'''
This function resolves the addresses for each
function associated with process injection and
sets the hooks
'''
def processInjectionHooks( imm ):
    hook = VirtualAllocEx()
    if ((imm.getAddress("Kernel32.VirtualAllocEx")) != -1):
        hook.add("VirtualAllocEx", imm.getAddress("kernel32.VirtualAllocEx"))
        imm.log("processInjectionHooks: kernel32.VirtualAllocEx set")
    else:
        imm.log("processInjectionHooks: kernel32.VirtualAllocEx not set")

    hook = CreateRemoteThread()
    if ((imm.getAddress("Kernel32.CreateRemoteThread")) != -1):
        hook.add("CreateRemoteThread", imm.getAddress("kernel32.CreateRemoteThread"))
        imm.log("processInjectionHooks: kernel32.CreateRemoteThread set")
    else:
        imm.log("processInjectionHooks: kernel32.CreateRemoteThread not set")

    hook = OpenProcess()
    if ((imm.getAddress("Kernel32.OpenProcess")) != -1 ):
        hook.add("OpenProcess", imm.getAddress("kernel32.OpenProcess"))
        imm.log("processInjectionHooks: kernel32.OpenProcess set")
    else:
        imm.log("processInjectionHooks: kernel32.OpenProcess not set")

    hook = ReadProcessMemory()
    if ((imm.getAddress("Kernel32.ReadProcessMemory")) != -1 ):
        hook.add("ReadProcessMemory", imm.getAddress("kernel32.ReadProcessMemory"))
        imm.log("processInjectionHooks: kernel32.ReadProcessMemory set")
    else:
        imm.log("processInjectionHooks: kernel32.ReadProcessMemory not set")

    hook = WriteProcessMemory()
    if ((imm.getAddress("Kernel32.WriteProcessMemory")) != -1 ):
        hook.add("WriteProcessMemory", imm.getAddress("kernel32.WriteProcessMemory"))
        imm.log("processInjectionHooks: kernel32.WriteProcessMemory set")
    else:
        imm.log("processInjectionHooks: kernel32.WriteProcessMemory not set")

    hook = CreateToolhelp32Snapshot()
    if ((imm.getAddress("Kernel32.CreateToolhelp32Snapshot")) != -1):
        hook.add("CreateToolhelp32Snapshot", imm.getAddress("kernel32.CreateToolhelp32Snapshot"))
        imm.log("processInjectionHooks: kernel32.CreateToolhelp32Snapshot set")
    else:
        imm.log("processInjectionHooks: kernel32.CreateToolhelp32Snapshot not set")

    hook = Process32First()
    if ((imm.getAddress("Kernel32.Process32First")) != -1):
        hook.add("Process32First", imm.getAddress("kernel32.Process32First"))
        imm.log("processInjectionHooks: kernel32.Process32First set")
    else:
        imm.log("processInjectionHooks: kernel32.Process32First not set")

    hook = Process32Next()
    if ((imm.getAddress("Kernel32.Process32Next")) != -1):
        hook.add("Process32Next", imm.getAddress("kernel32.Process32Next"))
        imm.log("processInjectionHooks: kernel32.Process32Next set")
    else:
        imm.log("processInjectionHooks: kernel32.Process32Next not set")

    hook = GetWindowThreadProcessId()
    if ((imm.getAddress("USER32.GetWindowThreadProcessId")) != -1):
        hook.add("GetWindowThreadProcessId", imm.getAddress("USER32.GetWindowThreadProcessId"))
        imm.log("processInjectionHooks: USER32.GetWindowThreadProcessId set")
    else:
        imm.log("processInjectionHooks: USER32.GetWindowThreadProcessId not set")

    hook = SetWindowsHookExA()
    if ((imm.getAddress("USER32.SetWindowsHookExA")) != -1):
        hook.add("SetWindowsHookExA", imm.getAddress("USER32.SetWindowsHookExA"))
        imm.log("processInjectionHooks: USER32.SetWindowsHookExA set")
    else:
        imm.log("processInjectionHooks: USER32.SetWindowsHookExA not set")

    hook = SetThreadContext()
    if ((imm.getAddress("kernel32.SetThreadContext")) != -1):
        hook.add("SetThreadContext", imm.getAddress("kernel32.SetThreadContext"))
        imm.log("processInjectionHooks: kernel32.SetThreadContext set")
    else:
        imm.log("processInjectionHooks: kernel32.SetThreadContext not set")

    hook = GetThreadContext()
    if ((imm.getAddress("kernel32.GetThreadContext")) != -1):
        hook.add("GetThreadContext", imm.getAddress("kernel32.GetThreadContext"))
        imm.log("processInjectionHooks: kernel32.GetThreadContext set")
    else:
        imm.log("processInjectionHooks: kernel32.GetThreadContext not set")

    hook = SetThreadExecutionState()
    if ((imm.getAddress("kernel32.SetThreadExecutionState")) != -1):
        hook.add("SetThreadExecutionState", imm.getAddress("kernel32.SetThreadExecutionState"))
        imm.log("processInjectionHooks: kernel32.SetThreadExecutionState set")
    else:
        imm.log("processInjectionHooks: kernel32.SetThreadExecutionState not set")

    hook = OpenThread()
    if ((imm.getAddress("kernel32.OpenThread")) != -1):
        hook.add("OpenThread", imm.getAddress("kernel32.OpenThread"))
        imm.log("processInjectionHooks: kernel32.OpenThread set")
    else:
        imm.log("processInjectionHooks: kernel32.OpenThread not set")

    hook = SuspendThread()
    if ((imm.getAddress("kernel32.SuspendThread")) != -1):
        hook.add("SuspendThread", imm.getAddress("kernel32.SuspendThread"))
        imm.log("processInjectionHooks: kernel32.SuspendThread set")
    else:
        imm.log("processInjectionHooks: kernel32.SuspendThread not set")

    hook = ResumeThread()
    if ((imm.getAddress("kernel32.ResumeThread")) != -1):
        hook.add("ResumeThread", imm.getAddress("kernel32.ResumeThread"))
        imm.log("processInjectionHooks: kernel32.ResumeThread set")
    else:
        imm.log("processInjectionHooks: kernel32.ResumeThread not set")

    hook = QueueUserAPC()
    if ((imm.getAddress("kernel32.QueueUserAPC")) != -1):
        hook.add("QueueUserAPC", imm.getAddress("kernel32.QueueUserAPC"))
        imm.log("processInjectionHooks: kernel32.QueueUserAPC set")
    else:
        imm.log("processInjectionHooks: kernel32.QueueUserAPC not set")

#makes a lot of noise
#    hook = ZwMapViewOfSection()
#    if ((imm.getAddress("ntdll.ZwMapViewOfSection")) != -1):
#        hook.add("ZwMapViewOfSection", imm.getAddress("ntdll.ZwMapViewOfSection"))
#    else:
#        imm.log("ntdll.ZwMapViewOfSection hook not set")

    hook = OpenProcessToken()
    if ((imm.getAddress("advapi32.OpenProcessToken")) != -1):
        hook.add("OpenProcessToken", imm.getAddress("advapi32.OpenProcessToken"))
        imm.log("processInjectionHooks: advapi32.OpenProcessToken set")
    else:
        imm.log("processInjectionHooks: advapi32.OpenProcessToken not set")

    hook = LookupPrivilegeValueA()
    if ((imm.getAddress("advapi32.LookupPrivilegeValueA")) != -1):
        hook.add("LookupPrivilegeValueA", imm.getAddress("advapi32.LookupPrivilegeValueA"))
        imm.log("processInjectionHooks: advapi32.LookupPrivilegeValueA set")
    else:
        imm.log("processInjectionHooks: advapi32.LookupPrivilegeValueA not set")

    hook = AdjustTokenPrivileges()
    if ((imm.getAddress("advapi32.AdjustTokenPrivileges")) != -1):
        hook.add("AdjustTokenPrivileges", imm.getAddress("advapi32.AdjustTokenPrivileges"))
        imm.log("processInjectionHooks: advapi32.AdjustTokenPrivileges set")
    else:
        imm.log("processInjectionHooks: advapi32.AdjustTokenPrivileges not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with process creation
'''
def processCreation():
    imm = immlib.Debugger()
    #Make the processCreation Window
    columnTitles = [ "Functions", "Args" ]
    processCreationWin = imm.createWindow( "Process Creation", columnTitles )
    imm.addKnowledge( "processCreationWin", processCreationWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("advapi32.CreateProcessAsUserA")) == -1):
        logItems = ["","advapi32.dll is not loaded, the some hooks will not be set"]
        processCreationWin.add( -1, logItems )
    if ((imm.getAddress("shell32.ShellExecuteA")) == -1):
        logItems = ["","shell32.dll is not loaded, the some hooks will not be set"]
        processCreationWin.add( -1, logItems )
    #Set the processCreation Hooks
    processCreationHooks( imm )
    imm.log("Process Creation Hooking Complete")

#########################################################################
'''
This function resolves the addresses for each
function associated with process creation and
sets the hooks
'''
def processCreationHooks( imm ):
    hook = CreateProcessA()
    if (( imm.getAddress("Kernel32.CreateProcessA")) != -1):
        hook.add("CreateProcessA", imm.getAddress("kernel32.CreateProcessA"))
        imm.log("processCreationHooks: kernel32.CreateProcessA set")
    else:
        imm.log("processCreationHooks: kernel32.CreateProcessA not set")

    hook = WinExec()
    if (( imm.getAddress("Kernel32.WinExec")) != -1 ):
        hook.add("WinExec", imm.getAddress("kernel32.WinExec"))
        imm.log("processCreationHooks: kernel32.WinExec set")
    else:
        imm.log("processCreationHooks: kernel32.WinExec not set")

    hook = CreateProcessAsUserA()
    if ((imm.getAddress("advapi32.CreateProcessAsUserA")) != -1):
        hook.add("CreateProcessAsUserA", imm.getAddress("advapi32.CreateProcessAsUserA"))
        imm.log("processCreationHooks: advapi32.CreateProcessAsUserA set")
    else:
        imm.log("processCreationHooks: advapi32.CreateProcessAsUserA not set")

    hook = CreateProcessWithLogonW()
    if ((imm.getAddress("advapi32.CreateProcessWithLogonW")) != -1):
        hook.add("CreateProcessWithLogonW", imm.getAddress("advapi32.CreateProcessWithLogonW"))
        imm.log("processCreationHooks: advapi32.CreateProcessWithLogonW set")
    else:
        imm.log("processCreationHooks: advapi32.CreateProcessWithLogonW not set")

    hook = ShellExecuteA()
    if ((imm.getAddress("shell32.ShellExecuteA")) != -1):
        hook.add("ShellExecuteA", imm.getAddress("shell32.ShellExecuteA"))
        imm.log("processCreationHooks: shell32.ShellExecuteA set")
    else:
        imm.log("processCreationHooks: shell32.ShellExecuteA not set")

    hook = CreateProcessInternalW()
    if ((imm.getAddress("kernel32.CreateProcessInternalW")) != -1):
        hook.add("CreateProcessInternalW", imm.getAddress("kernel32.CreateProcessInternalW"))
        imm.log("processCreationHooks: kernel32.CreateProcessInternalW set")
    else:
        imm.log("processCreationHooks: kernel32.CreateProcessInternalW not set")

    hook = CreateProcessAsUserSecure()
    if ((imm.getAddress("advapi32.CreateProcessAsUserSecure")) != -1):
        hook.add("CreateProcessAsUserSecure", imm.getAddress("advapi32.CreateProcessAsUserSecure"))
        imm.log("processCreationHooks: advapi32.CreateProcessAsUserSecure set")
    else:
        imm.log("processCreationHooks: advapi32.CreateProcessAsUserSecure not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with service creation
'''
def serviceCreation():
    imm = immlib.Debugger()
    #Make the serviceCreation Window
    columnTitles = [ "Functions", "Args" ]
    serviceCreationWin = imm.createWindow( "Service Creation", columnTitles )
    imm.addKnowledge( "serviceCreationWin", serviceCreationWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("advapi32.OpenSCManagerA")) == -1):
        logItems = ["","advapi32.dll is not loaded, the some hooks will not be set"]
        serviceCreationWin.add( -1, logItems )
    #Set the serviceCreation Hooks
    serviceCreationHooks( imm )
    imm.log("Service Creation Hooking Complete")

#########################################################################
'''
This function resolves the addresses for each
function associated with service creation and
sets the hooks
'''
def serviceCreationHooks( imm ):
    hook = OpenSCManagerA()
    if ((imm.getAddress("advapi32.OpenSCManagerA")) != -1):
        hook.add("OpenSCManagerA", imm.getAddress("advapi32.OpenSCManagerA"))
        imm.log("serviceCreationHooks: advapi32.OpenSCManagerA set")
    else:
        imm.log("serviceCreationHooks: advapi32.OpenSCManagerA not set")

    hook = StartServiceA()
    if ((imm.getAddress("advapi32.StartServiceA")) != -1):
        hook.add("StartServiceA", imm.getAddress("advapi32.StartServiceA"))
        imm.log("serviceCreationHooks: advapi32.StartServiceA set")
    else:
        imm.log("serviceCreationHooks: advapi32.StartServiceA not set")

    hook = ControlService()
    if ((imm.getAddress("advapi32.ControlService")) != -1):
        hook.add("ControlService", imm.getAddress("advapi32.ControlService"))
        imm.log("serviceCreationHooks: advapi32.ControlService set")
    else:
        imm.log("serviceCreationHooks: advapi32.ControlService not set")

    hook = OpenServiceA()
    if ((imm.getAddress("advapi32.OpenServiceA")) != -1):
        hook.add("OpenServiceA", imm.getAddress("advapi32.OpenServiceA"))
        imm.log("serviceCreationHooks: advapi32.OpenServiceA set")
    else:
        imm.log("serviceCreationHooks: advapi32.OpenServiceA not set")

    hook = ChangeServiceConfigA()
    if ((imm.getAddress("advapi32.ChangeServiceConfigA")) != -1):
        hook.add("ChangeServiceConfigA", imm.getAddress("advapi32.ChangeServiceConfigA"))
        imm.log("serviceCreationHooks: advapi32.ChangeServiceConfigA set")
    else:
        imm.log("serviceCreationHooks: advapi32.ChangeServiceConfigA not set")

    hook = ChangeServiceConfig2A()
    if ((imm.getAddress("advapi32.ChangeServiceConfig2A")) != -1):
        hook.add("ChangeServiceConfig2A", imm.getAddress("advapi32.ChangeServiceConfig2A"))
        imm.log("serviceCreationHooks: advapi32.ChangeServiceConfig2A set")
    else:
        imm.log("serviceCreationHooks: advapi32.ChangeServiceConfig2A not set")

    hook = DeleteService()
    if ((imm.getAddress("advapi32.DeleteService")) != -1):
        hook.add("DeleteService", imm.getAddress("advapi32.DeleteService"))
        imm.log("serviceCreationHooks: advapi32.DeleteService set")
    else:
        imm.log("serviceCreationHooks: advapi32.DeleteService not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with keylogging
'''
def keyLoggAttempt():
    imm = immlib.Debugger()
    #Make the keyLoggAttempt Window
    columnTitles = [ "Functions", "Args" ]
    keyLoggAttemptWin = imm.createWindow( "Keylogg Attempt", columnTitles )
    imm.addKnowledge( "keyLoggAttemptWin", keyLoggAttemptWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("USER32.SetWindowsHookExA")) == -1):
        logItems = ["","USER32.dll is not loaded, the some hooks will not be set"]
        keyLoggAttemptWin.add( -1, logItems )
    #Set the keyLoggAttempt Hooks
    keyLoggAttemptHooks( imm )
    imm.log("Keylogg Attempt Hooking Complete")

#########################################################################
'''
This function resolves the addresses for each
function associated with keylogging and
sets the hooks
'''
def keyLoggAttemptHooks( imm ):
#SetWindowsHookExA can also be used in process injection and I think I will keep it there
#    hook = SetWindowsHookExA()
#    if ((imm.getAddress("USER32.SetWindowsHookExA")) != -1):
#        hook.add("SetWindowsHookExA", imm.getAddress("USER32.SetWindowsHookExA"))

    hook = GetKeyboardState()
    if ((imm.getAddress("USER32.GetKeyboardState")) != -1):
        hook.add("GetKeyboardState", imm.getAddress("USER32.GetKeyboardState"))
        imm.log("keyLoggAttemptHooks: USER32.GetKeyboardState set")
    else:
        imm.log("keyLoggAttemptHooks: USER32.GetKeyboardState not set")

    hook = GetKeyState()
    if ((imm.getAddress("USER32.GetKeyState")) != -1):
        hook.add("GetKeyState", imm.getAddress("USER32.GetKeyState"))
        imm.log("keyLoggAttemptHooks: USER32.GetKeyState set")
    else:
        imm.log("keyLoggAttemptHooks: USER32.GetKeyState not set")

    hook = GetAsyncKeyState()
    if ((imm.getAddress("USER32.GetAsyncKeyState")) != -1):
        hook.add("GetAsyncKeyState", imm.getAddress("USER32.GetAsyncKeyState"))
        imm.log("keyLoggAttemptHooks: USER32.GetAsyncKeyState set")
    else:
        imm.log("keyLoggAttemptHooks: USER32.GetAsyncKeyState not set")

    hook = GetForegroundWindow()
    if ((imm.getAddress("USER32.GetForegroundWindow")) != -1):
        hook.add("GetForegroundWindow", imm.getAddress("USER32.GetForegroundWindow"))
        imm.log("keyLoggAttemptHooks: USER32.GetForegroundWindow set")
    else:
        imm.log("keyLoggAttemptHooks: USER32.GetForegroundWindow not set")

#########################################################################
'''
This function is called from main and
it creates the window and sets the hooks
associated with general malicious activity
'''
def malIndicator():
    imm = immlib.Debugger()
    #Make the malIndicator Window
    columnTitles = [ "Functions", "Args" ]
    malIndicatorWin = imm.createWindow( "Common Malware Methods", columnTitles )
    imm.addKnowledge( "malIndicatorWin", malIndicatorWin, force_add=0x1)
    #Check to see if the dll is loaded, Lazy should fix later
    if ((imm.getAddress("kernel32.VirtualProtect")) == -1):
        logItems = ["","kernel32.dll is not loaded, the some hooks will not be set"]
        malIndicatorWin.add( -1, logItems )
    if ((imm.getAddress("ntdll.ZwLoadDriver")) == -1):
        logItems = ["","ntdll.dll is not loaded, the some hooks will not be set"]
        malIndicatorWin.add( -1, logItems )
    #Set the malIndicator Hooks
    malIndicatorHooks( imm )
    imm.log("Common Malware Method Hooking Complete")

#########################################################################
'''
This function resolves the addresses for each
function associated with potentially malicious
activity and sets the hooks
'''
def malIndicatorHooks( imm ):
    hook = VirtualProtect()
    if ((imm.getAddress("kernel32.VirtualProtect")) != -1):
        hook.add("VirtualProtect", imm.getAddress("kernel32.VirtualProtect"))
        imm.log("malIndicatorHooks: kernel32.VirtualProtect set")
    else:
        imm.log("malIndicatorHooks: kernel32.VirtualProtect not set")

    hook = LoadLibraryA()
    if ((imm.getAddress("kernel32.LoadLibraryA")) != -1):
        hook.add("LoadLibraryA", imm.getAddress("kernel32.LoadLibraryA"))
        imm.log("malIndicatorHooks: kernel32.LoadLibraryA set")
    else:
        imm.log("malIndicatorHooks: kernel32.LoadLibraryA not set")

    hook = GetProcAddress()
    if ((imm.getAddress("kernel32.GetProcAddress")) != -1):
        hook.add("GetProcAddress", imm.getAddress("kernel32.GetProcAddress"))
        imm.log("malIndicatorHooks: kernel32.GetProcAddress set")
    else:
        imm.log("malIndicatorHooks: kernel32.GetProcAddress not set")

    hook = GetModuleHandleA()
    if ((imm.getAddress("kernel32.GetModuleHandleA")) != -1):
        hook.add("GetModuleHandleA", imm.getAddress("kernel32.GetModuleHandleA"))
        imm.log("malIndicatorHooks: kernel32.GetModuleHandleA set")
    else:
        imm.log("malIndicatorHooks: kernel32.GetModuleHandleA not set")

    hook = ZwLoadDriver()
    if ((imm.getAddress("ntdll.ZwLoadDriver")) != -1):
        hook.add("ZwLoadDriver", imm.getAddress("ntdll.ZwLoadDriver"))
        imm.log("malIndicatorHooks: ntdll.ZwLoadDriver set")
    else:
        imm.log("malIndicatorHooks: ntdll.ZwLoadDriver not set")

    hook = ZwSetSystemInformation()
    if ((imm.getAddress("ntdll.ZwSetSystemInformation")) != -1):
        hook.add("ZwSetSystemInformation", imm.getAddress("ntdll.ZwSetSystemInformation"))
        imm.log("malIndicatorHooks: ntdll.ZwSetSystemInformation set")
    else:
        imm.log("malIndicatorHooks: ntdll.ZwSetSystemInformation not set")

    #Hook ret for LoadLibrary
    hook = LoadLibraryRet()
    if ((imm.getAddress("kernel32.LoadLibraryA")) == -1):
        imm.log("malIndicatorHooks: kernel32.LoadLibraryARet not set")
        return
    address = imm.getAddress("kernel32.LoadLibraryA")
    f = imm.getFunction( address )
    blocks = f.getEnd()
    for bb in blocks:
        for opcode in blocks[0].getInstructions( imm ):
            if opcode.isRet():
                hook.add("LoadLibraryRet", opcode.getAddress())
                imm.log("malIndicatorHooks: kernel32.LoadLibraryRet set")

#########################################################################
'''
This function is called from main
it sets actual break points on any
function which can be used to perform
execution redirection
'''
def breakOnExecutionRedirection():
    imm = immlib.Debugger()
    imm.addKnowledge("breakOnExecutionRedirection", True, force_add=0x1)
    setBreakOnExecutionRedirection( imm )

##########################################################################
'''
This function sets breakpoints on
api call that can be used to perform
execution redirection
'''
def setBreakOnExecutionRedirection( imm ):
    if((imm.getAddress("advapi32.StartServiceA")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.StartServiceA"))
        imm.log("setBreakOnExecutionRedirection: advapi32.StartServiceA set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.StartServiceA not set")

    if((imm.getAddress("advapi32.StartServiceW")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.StartServiceW"))
        imm.log("setBreakOnExecutionRedirection: advapi32.StartServiceW set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.StartServiceW not set")

    if((imm.getAddress("advapi32.CreateProcessAsUserSecure")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.CreateProcessAsUserSecure"))
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserSecure set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserSecure not set")

    if((imm.getAddress("kernel32.CreateProcessInternalW")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.CreateProcessInternalW"))
        imm.log("setBreakOnExecutionRedirection: CreateProcessInternalW set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessInternalW not set")

    if((imm.getAddress("kernel32.CreateProcessInternalA")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.CreateProcessInternalA"))
        imm.log("setBreakOnExecutionRedirection: CreateProcessInternalA set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessInternalA not set")

    if((imm.getAddress("shell32.ShellExecuteA")) != -1):
        imm.setBreakpoint( imm.getAddress("shell32.ShellExecuteA"))
        imm.log("setBreakOnExecutionRedirection: shell32.ShellExecuteA set")
    else:
        imm.log("setBreakOnExecutionRedirection: shell32.ShellExecuteA not set")

    if((imm.getAddress("shell32.ShellExecuteW")) != -1):
        imm.setBreakpoint( imm.getAddress("shell32.ShellExecuteW"))
        imm.log("setBreakOnExecutionRedirection: shell32.ShellExecuteW set")
    else:
        imm.log("setBreakOnExecutionRedirection: shell32.ShellExecuteW not set")

    if((imm.getAddress("advapi32.CreateProcessWithLogonW")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.CreateProcessWithLogonW"))
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessWithLogonW set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessWithLogonW not set")

    if((imm.getAddress("advapi32.CreateProcessAsUserA")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.CreateProcessAsUserA"))
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserA set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserA not set")

    if((imm.getAddress("advapi32.CreateProcessAsUserW")) != -1):
        imm.setBreakpoint( imm.getAddress("advapi32.CreateProcessAsUserW"))
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserW set")
    else:
        imm.log("setBreakOnExecutionRedirection: advapi32.CreateProcessAsUserW not set")

    if((imm.getAddress("kernel32.WinExec")) != -1 ):
        imm.setBreakpoint( imm.getAddress("kernel32.WinExec"))
        imm.log("setBreakOnExecutionRedirection: kernel32.WinExec set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.WinExec not set")

    if((imm.getAddress("kernel32.CreateProcessA")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.CreateProcessA"))
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessA set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessA not set")

    if((imm.getAddress("kernel32.CreateProcessW")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.CreateProcessW"))
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessW set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateProcessW not set")

    if((imm.getAddress("kernel32.QueueUserAPC")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.QueueUserAPC"))
        imm.log("setBreakOnExecutionRedirection: kernel32.QueueUserAPC set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.QueueUserAPC not set")

    if((imm.getAddress("kernel32.ResumeThread")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.ResumeThread"))
        imm.log("setBreakOnExecutionRedirection: kernel32.ResumeThread set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.ResumeThread not set")

    if((imm.getAddress("USER32.SetWindowsHookExA")) != -1):
        imm.setBreakpoint( imm.getAddress("USER32.SetWindowsHookExA"))
        imm.log("setBreakOnExecutionRedirection: USER32.SetWindowsHookExA set")
    else:
        imm.log("setBreakOnExecutionRedirection: USER32.SetWindowsHookExA not set")

    if((imm.getAddress("USER32.SetWindowsHookExW")) != -1):
        imm.setBreakpoint( imm.getAddress("USER32.SetWindowsHookExW"))
        imm.log("setBreakOnExecutionRedirection: USER32.SetWindowsHookExW set")
    else:
        imm.log("setBreakOnExecutionRedirection: USER32.SetWindowsHookExW not set")

    if((imm.getAddress("kernel32.CreateRemoteThread")) != -1):
        imm.setBreakpoint( imm.getAddress("kernel32.CreateRemoteThread"))
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateRemoteThread set")
    else:
        imm.log("setBreakOnExecutionRedirection: kernel32.CreateRemoteThread not set")

#########################################################################
'''
helper function
'''
def getASCII(wString):
    asciiString = ""
    i = 0
    while( i < len(wString)):
        asciiString+=wString[i]
        i+=2
    return asciiString

#########################################################################
'''
duh
'''
def usage():
    imm = immlib.Debugger()
    imm.error("Usage:  !BlackManta -[Options]\n\nOptions:\n-1 : Registry Access\n-2 : File Access \n-3 : DNS Request\n-4 : General Socket Communication\n-5 : Promiscuous Mode Attempt\n-6 : Packet Spoofing Attempt\n-7 : HTTP Tunneling Attempt\n-8 : Process Injection\n-9 : Process Creation\n-a : Service Creation\n-b : Keylogging Attempt\n-c : Malicious Indicators\n-d : All of the Above(SLOW)\n-e : Break on Execution Redirection\n-? : See Log For Verbose Usage")

##########################################################################
'''
I think this is the longest function
in the whole damn script
'''
def verboseLog():
    imm = immlib.Debugger()
    imm.log("  ")
    imm.log("Usage: !BlackManta -[Options]")
    imm.log("  ")
    imm.log(" [Options] ")
    imm.log(" -1 : Registry API Hooks")
    imm.log("       Advapi32.RegConnectRegistryA")
    imm.log("       Advapi32.RegQueryValueExA")
    imm.log("       Advapi32.RegCreateKeyExA")
    imm.log("       Advapi32.RegSetValueExA")
    imm.log("       Advapi32.RegOpenKeyExA")
    imm.log("       Advapi32.RegCloseKey")
    imm.log("  ")
    imm.log(" -2 : File API Hooks")
    imm.log("       kernel32.WriteFileEx")
    imm.log("       kernel32.DeleteFileA")
    imm.log("       kernel32.MoveFileExA")
    imm.log("       kernel32.CreateFileA")
    imm.log("       kernel32.ReadFileEx")
    imm.log("       kernel32.WriteFile")
    imm.log("       kernel32.ReadFile")
    imm.log("  ")
    imm.log(" -3 : DNS Request API Hooks")
    imm.log("       dnsapi.DnsQuery_UTF8")
    imm.log("       dnsapi.DnsQuery_A")
    imm.log("       dnsapi.DnsQuery_W")
    imm.log("  ")
    imm.log(" -4 : General Socket Communication API Hooks")
    imm.log("       WS2_32.WSAStartup")
    imm.log("       WS2_32.recvfrom")
    imm.log("       WS2_32.WSARecv")
    imm.log("       WS2_32.WSASend")
    imm.log("       WS2_32.connect")
    imm.log("       WS2_32.accept")
    imm.log("       WS2_32.listen")
    imm.log("       WS2_32.recv")
    imm.log("       WS2_32.send")
    imm.log("  ")
    imm.log(" -5 : Promiscuous Mode API Hooks")
    imm.log("       WS2_32.ioctlsocket")
    imm.log("       WS2_32.WSASocketA")
    imm.log("       WS2_32.WSAIoctl")
    imm.log("       WS2_32.socket")
    imm.log("       WS2_32.bind")
    imm.log("  ")
    imm.log(" -6 : Packet Spoofing API Hooks")
    imm.log("       packet.PacketAllocatePacket")
    imm.log("       packet.PacketOpenAdapter")
    imm.log("       packet.PacketInitPacket")
    imm.log("       packet.PacketSendPacket")
    imm.log("       packet.PacketSetBuff")
    imm.log("  ")
    imm.log(" -7 : HTTP Tunneling API Hooks")
    imm.log("       WININET.HttpAddRequestHeadersA")
    imm.log("       WININET.InternetReadFileExA")
    imm.log("       WININET.InternetOpenUrlA")
    imm.log("       WININET.InternetConnectA")
    imm.log("       WININET.HttpOpenRequestA")
    imm.log("       WININET.InternetReadFile")
    imm.log("       WININET.InternetOpenA")
    imm.log("       urlmon.URLDownloadToFileA")
    imm.log("  ")
    imm.log(" -8 : Process Injection API Hooks")
    imm.log("       kernel32.CreateToolhelp32Snapshot")
    imm.log("       kernel32.SetThreadExecutionState")
    imm.log("       kernel32.CreateRemoteThread")
    imm.log("       kernel32.ReadProcessMemory")
    imm.log("       kernel32.WriteProcessMemory")
    imm.log("       kernel32.SetThreadContext")
    imm.log("       kernel32.GetThreadContext")
    imm.log("       kernel32.VirtualAllocEx")
    imm.log("       kernel32.Process32First")
    imm.log("       kernel32.Process32Next")
    imm.log("       kernel32.SuspendThread")
    imm.log("       kernel32.ResumeThread")
    imm.log("       kernel32.QueueUserAPC")
    imm.log("       kernel32.OpenProcess")
    imm.log("       kernel32.OpenThread")
    imm.log("       advapi32.LookupPrivilegeValueA")
    imm.log("       advapi32.AdjustTokenPrivileges")
    imm.log("       advapi32.OpenProcessToken")
    imm.log("       user32.GetWindowThreadProcessId")
    imm.log("       user32.SetWindowsHookExA")
    imm.log("       ntdll.ZwMapViewOfSection")
    imm.log("  ")
    imm.log(" -9 : Process Creation API Hooks")
    imm.log("       kernel32.CreateProcessInternalW")
    imm.log("       kernel32.CreateProcessA")
    imm.log("       kernel32.WinExec")
    imm.log("       advapi32.CreateProcessAsUserSecure")
    imm.log("       advapi32.CreateProcessWithLogonW")
    imm.log("       advapi32.CreateProcessAsUserA")
    imm.log("       shell32.ShellExecuteA")
    imm.log("  ")
    imm.log(" -a : Service Creation API Hooks")
    imm.log("       advapi32.ChangeServiceConfig2A")
    imm.log("       advapi32.ChangeServiceConfigA")
    imm.log("       advapi32.OpenSCManagerA")
    imm.log("       advapi32.ControlService")
    imm.log("       advapi32.StartServiceA")
    imm.log("       advapi32.DeleteService")
    imm.log("       advapi32.OpenServiceA")
    imm.log("  ")
    imm.log(" -b : Key Logging API Hooks")
    imm.log("       user32.GetForegroundWindow")
    imm.log("       user32.GetKeyboardState")
    imm.log("       user32.GetAsyncKeyState")
    imm.log("       user32.GetKeyState")
    imm.log("  ")
    imm.log(" -c : Potentially Malicious Indicators")
    imm.log("       kernel32.GetModuleHandleA")
    imm.log("       kernel32.VirtualProtect")
    imm.log("       kernel32.GetProcAddress")
    imm.log("       kernel32.CreateMutexA")
    imm.log("       kernel32.LoadLibraryA")
    imm.log("       ntdll.ZwSetSystemInformation")
    imm.log("       ntdll.ZwLoadDriver")
    imm.log("  ")
    imm.log(" -d : All of the Above")
    imm.log("  ")
    imm.log(" -e : Break on Execution Redirection (Places BP on the following API calls)")
    imm.log("       kernel32.CreateProcessInternalW")
    imm.log("       kernel32.CreateProcessInternalA")
    imm.log("       kernel32.CreateRemoteThread")
    imm.log("       kernel32.CreateProcessA")
    imm.log("       kernel32.CreateProcessW")
    imm.log("       kernel32.QueueUserAPC")
    imm.log("       kernel32.ResumeThread")
    imm.log("       kernel32.WinExec")
    imm.log("       advapi32.CreateProcessAsUserSecure")
    imm.log("       advapi32.CreateProcessWithLogonW")
    imm.log("       advapi32.CreateProcessAsUserA")
    imm.log("       advapi32.CreateProcessAsUserW")
    imm.log("       advapi32.StartServiceA")
    imm.log("       advapi32.StartServiceW")
    imm.log("       user32.SetWindowsHookExA")
    imm.log("       user32.SetWindowsHookExW")
    imm.log("       shell32.ShellExecuteA")
    imm.log("       shell32.ShellExecuteW")
    imm.log("  ")
    imm.log(" -? : Display This Message")
    imm.log("  ")

##########################################################################
def main(args):
    if args:
        imm = immlib.Debugger()
        imm.ignoreSingleStep(flag="CONTINUE")
        imm.deleteBreakpoint(0x00000000, 0xffffffff)
        knowledge = imm.listKnowledge()
        for know in knowledge:
            imm.forgetKnowledge(know)

        if ((str(args).find("-1")) > 0):
            regMon()
        if ((str(args).find("-2")) > 0):
            fileMon()
        if ((str(args).find("-3")) > 0):
            dnsRequest()
        if ((str(args).find("-4")) > 0):
            generalSocketComm()
        if ((str(args).find("-5")) > 0):
            promiscuousMode()
        if ((str(args).find("-6")) > 0):
            packetSpoofing()
        if ((str(args).find("-7")) > 0):
            httpTunneling()
        if ((str(args).find("-8")) > 0):
            processInjection()
        if ((str(args).find("-9")) > 0):
            processCreation()
        if ((str(args).upper().find("-A")) > 0 ):
            serviceCreation()
        if ((str(args).upper().find("-B")) > 0 ):
            keyLoggAttempt()
        if ((str(args).upper().find("-C")) > 0 ):
            malIndicator()
        if ((str(args).upper().find("-D")) > 0 ):
            regMon()
            fileMon()
            dnsRequest()
            generalSocketComm()
            promiscuousMode()
            packetSpoofing()
            httpTunneling()
            processInjection()
            processCreation()
            serviceCreation()
            keyLoggAttempt()
            malIndicator()
        if ((str(args).upper().find("-E")) > 0 ):
            breakOnExecutionRedirection()
        if ((str(args).find("-?")) > 0):
            verboseLog()
    else:
        usage()
    return "BlackManta Complete"


if __name__=="__main__":
    print "This module is for use within Immunity Debugger only"
