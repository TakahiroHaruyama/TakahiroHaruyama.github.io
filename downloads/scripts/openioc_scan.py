# openioc_scan Volatility plugin
# based on ioc_writer (https://github.com/mandiant/ioc_writer) and pyioc (https://github.com/jeffbryner/pyioc)
# Copyright (c) 2014 Takahiro Haruyama (@cci_forensics)
# http://takahiroharuyama.github.io/

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32.tasks as tasks
import volatility.obj as obj
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.malware.psxview as psxview
import volatility.plugins.malware.svcscan as svcscan
import volatility.plugins.netscan as netscan
import volatility.plugins.overlays.windows.tcpip_vtypes as tcpip_vtypes
import volatility.constants as constants
import volatility.plugins.registry.hivelist as hivelist
import volatility.plugins.registry.shimcache as shimcache
import volatility.win32.hive as hivemod
import volatility.win32.rawreg as rawreg
import volatility.plugins.taskmods as taskmods
import volatility.commands as commands

import glob, os, re, sqlite3, urllib, socket, time
from lxml import etree as et
from ioc_writer import ioc_api
import colorama
colorama.init()

g_version = '2014/08/08'
g_cache_path = ''
READ_BLOCKSIZE = 1024 * 1024 * 10

# copied from netscan
AF_INET = 2
AF_INET6 = 0x17
inaddr_any = utils.inet_ntop(socket.AF_INET, '\0' * 4)
inaddr6_any = utils.inet_ntop(socket.AF_INET6, '\0' * 16)

# copied from malfind
class MalwareObjectClases(obj.ProfileModification):
    before = ['WindowsObjectClasses']
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.object_classes.update({
            '_EPROCESS': malfind.MalwareEPROCESS,
        })

class Timer(object):
    def __init__(self, verbose=False):
        self.verbose = verbose

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        self.end = time.time()
        self.secs = self.end - self.start
        self.msecs = self.secs * 1000  # millisecs
        if self.verbose:
            print 'elapsed time: %f ms' % self.msecs

class ItemUtil:
    def is_condition_bool(self, condition):
        supported_conditions = ['is', 'contains']
        if condition in supported_conditions:
            return True
        else:
            return False

    def is_condition_string(self, condition):
        supported_conditions = ['is', 'contains', 'matches', 'starts-with', 'ends-with']
        if condition in supported_conditions:
            return True
        else:
            return False

    def is_condition_integer(self, condition):
        supported_conditions = ['is', 'greater-than', 'less-than']
        if condition in supported_conditions:
            return True
        else:
            return False

    def make_regex(self, content, preserve_case):
        content_ur = ur'{0}'.format(content)
        if preserve_case == 'true':
            #pattern = re.compile(content.decode('ascii'), re.UNICODE)
            pattern = re.compile(content_ur, re.UNICODE)
        else:
            #pattern = re.compile(content.decode('ascii'), re.IGNORECASE | re.UNICODE)
            pattern = re.compile(content_ur, re.IGNORECASE | re.UNICODE)
        return pattern

    def check_string(self, target, content, condition, preserve_case):
        if condition == 'matches':
            pattern = self.make_regex(content, preserve_case)
            if pattern.search(target) is not None:
                return True
        else:
            if preserve_case == 'false':
                target = target.lower()
                content = content.lower()
            if condition == 'is':
                if target == content:
                    return True
            elif condition == 'contains':
                if target.find(content) != -1:
                    return True
            elif condition == 'starts-with':
                if target.startswith(content):
                    return True
            elif condition == 'ends-with':
                if target.endswith(content):
                    return True
        return False

    def check_strings(self, target_list, content, condition, preserve_case):
        for target in target_list:
            if self.check_string(target, content, condition, preserve_case):
                return True
        return False

    def extract_unicode(self, data):
        pat = re.compile(ur'(?:[\x20-\x7E][\x00]){4,}')
        return list(set([w.decode('utf-16le') for w in pat.findall(data)]))

    def extract_ascii(self, data):
        pat = re.compile(r'(?:[\x20-\x7E]){4,}')
        return list(set([w.decode('ascii') for w in pat.findall(data)]))

    def check_integer(self, target, content, condition, preserve_case):
        if condition == 'is':
            if target == int(content):
                return True
        elif condition == 'greater-than':
            if target > int(content):
                return True
        elif condition == 'less-than':
            if target < int(content):
                return True
        return False

    def check_integers(self, target_list, content, condition, preserve_case):
        for target in target_list:
            if self.check_integer(target, content, condition, preserve_case):
                return True
        return False

    def fetchall_from_db(self, cur, table, column):
        debug.debug("{0} already done. Results reused".format(table))
        sql = "select {0} from {1}".format(column, table)
        cur.execute(sql)
        return [record[0] for record in cur.fetchall()]

    def fetchone_from_db(self, cur, table, column):
        debug.debug("{0} already done. Results reused".format(table))
        sql = "select {0} from {1}".format(column, table)
        cur.execute(sql)
        return cur.fetchone()[0]

class ProcessItem(impscan.ImpScan, netscan.Netscan, malfind.Malfind):
    def __init__(self, process, cur, _config):
        self.process = process
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.forwarded_imports = { # for impscan
            "RtlGetLastWin32Error" : "kernel32.dll!GetLastError",
            "RtlSetLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlRestoreLastWin32Error" : "kernel32.dll!SetLastError",
            "RtlAllocateHeap" : "kernel32.dll!HeapAlloc",
            "RtlReAllocateHeap" : "kernel32.dll!HeapReAlloc",
            "RtlFreeHeap" : "kernel32.dll!HeapFree",
            "RtlEnterCriticalSection" : "kernel32.dll!EnterCriticalSection",
            "RtlLeaveCriticalSection" : "kernel32.dll!LeaveCriticalSection",
            "RtlDeleteCriticalSection" : "kernel32.dll!DeleteCriticalSection",
            "RtlZeroMemory" : "kernel32.dll!ZeroMemory",
            "RtlSizeHeap" : "kernel32.dll!HeapSize",
            "RtlUnwind" : "kernel32.dll!RtlUnwind",
            }
        self.util = ItemUtil()

    def read_without_zero_page(self, vad, address_space):
        PAGE_SIZE = 0x1000
        all_zero_page = "\x00" * PAGE_SIZE

        offset = 0
        data = ''
        while offset < vad.Length:
            next_addr = vad.Start + offset
            if address_space.is_valid_address(next_addr):
                page = address_space.read(next_addr, PAGE_SIZE)
                if page != all_zero_page:
                    data += page
            offset += PAGE_SIZE
        return data

    def check_done(self, item):
        sql = "select {0} from done where pid = ?".format(item)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        return self.cur.fetchone()

    def update_done(self, item):
        sql = "update done set {0} = ? where pid = ?".format(item)
        self.cur.execute(sql, (True, self.process.UniqueProcessId.v()))

    def update_all_done(self, item):
        sql = "update done set {0} = ?".format(item)
        self.cur.execute(sql, (True, ))

    def fetchall_from_db(self, table, column):
        debug.debug("{0} already done. Results reused (pid={1})".format(table, self.process.UniqueProcessId))
        sql = "select {0} from {1} where pid = ?".format(column, table)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        return [record[0] for record in self.cur.fetchall()]

    def fetchone_from_db(self, table, column):
        debug.debug("{0} already done. Results reused (pid={1})".format(table, self.process.UniqueProcessId))
        sql = "select {0} from {1} where pid = ?".format(column, table)
        self.cur.execute(sql, (self.process.UniqueProcessId.v(),))
        return self.cur.fetchone()[0]

    def detect_code_injections(self):
        injected = []
        debug.info("[time-consuming task] detecting code injections...(pid={0})".format(self.process.UniqueProcessId))
        for vad, address_space in self.process.get_vads(vad_filter = self.process._injection_filter):
            if self._is_vad_empty(vad, address_space):
                continue
            self.cur.execute("insert into injected values (?, ?, ?)", (self.process.UniqueProcessId.v(), vad.Start, vad.Length))
            injected.append([vad.Start, vad.Length])
        self.update_done('injected')
        return len(injected)

    def SectionList_MemorySection_Injected(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in ProcessItem/SectionList/MemorySection/Injected'.format(condition))
            return False

        (done,) = self.check_done('injected')
        if int(done):
            counts = self.fetchone_from_db('injected', 'count(*)')
        else:
            counts = self.detect_code_injections()

        if (counts > 0 and content.lower() == 'true') or (counts == 0 and content.lower() == 'false'):
            return True
        else:
            return False

    def extract_strings(self):
        debug.info("[time-consuming task] extracting strings from VADs (pid={0})".format(self.process.UniqueProcessId))
        strings = []

        for vad, address_space in self.process.get_vads(skip_max_commit = True):
            data = self.read_without_zero_page(vad, address_space)
            if len(data) == 0:
                continue
            elif len(data) > READ_BLOCKSIZE:
                debug.warning('data size in VAD is more than READ_BLOCKSIZE (pid{0})'.format(self.process.UniqueProcessId))
            extracted = list(set(self.util.extract_unicode(data) + self.util.extract_ascii(data)))
            strings.extend(extracted)

        records = ((self.process.UniqueProcessId.v(), string) for string in strings)
        self.cur.executemany("insert or ignore into strings values (?, ?)", records)
        self.update_done('strings')
        return strings

    def check_and_extract_strings(self, content, condition, preserve_case):
        (done,) = self.check_done('strings')
        if int(done):
            strings = self.fetchall_from_db('strings', 'string')
        else:
            strings = self.extract_strings()
        return self.util.check_strings(strings, content, condition, preserve_case)

    def StringList_string(self, content, condition, preserve_case):
        '''
        condition: is/contains/matches(regex)/starts-with/ends-with
        preserve_case: true/false
        '''
        result = False

        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/StringList/string'.format(condition))
            return False

        result = self.check_and_extract_strings(content, condition, preserve_case)
        if result == False and condition == 'matches': # for searching binary sequences
            pattern = self.util.make_regex(content, preserve_case)
            (done,) = self.check_done('vaddump')
            if int(done):
                debug.debug("vaddump already done. Results reused (pid={0})".format(self.process.UniqueProcessId))
                f = open(os.path.join(g_cache_path, 'vaddump_pid' + str(self.process.UniqueProcessId)) + '.bin', 'rb')

                i = 0
                overlap = 1024
                self.cur.execute("select size from vaddump where pid = ?", (self.process.UniqueProcessId.v(),))
                maxlen = self.cur.fetchone()[0]
                while i < maxlen:
                    to_read = min(READ_BLOCKSIZE + overlap, maxlen - i)
                    f.seek(i)
                    data = f.read(to_read)
                    if data:
                        if pattern.search(data) is not None:
                            return True
                    i += READ_BLOCKSIZE
                return False

            debug.info("[time-consuming task] dumping VADs for regex search... (pid={0})".format(self.process.UniqueProcessId))
            f = open(os.path.join(g_cache_path, 'vaddump_pid' + str(self.process.UniqueProcessId)) + '.bin', 'wb')
            size = 0
            for vad, address_space in self.process.get_vads(skip_max_commit = True):
                data = self.read_without_zero_page(vad, address_space)
                if len(data) == 0:
                    continue
                elif len(data) > READ_BLOCKSIZE:
                    debug.warning('data size in VAD is more than READ_BLOCKSIZE (pid{0})'.format(self.process.UniqueProcessId))
                if pattern.search(data) is not None:
                    result = True
                f.write(data)
                size += len(data)
            f.flush()
            f.close()
            self.cur.execute("insert into vaddump values (?, ?)", (self.process.UniqueProcessId.v(), size))
            self.update_done('vaddump')

        return result

    # based on impscan.py
    def SectionList_MemorySection_PEInfo_ImportedModules_Module_ImportedFunctions_string(self, content, condition, preserve_case):
        result = False

        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/SectionList/MemorySection/PEInfo/ImportedModules/Module/ImportedFunctions/string'.format(condition))
            return False

        (done,) = self.check_done('impfunc')
        if int(done):
            imp_funcs = self.fetchall_from_db('impfunc', 'func_name')
            return self.util.check_strings(imp_funcs, content, condition, preserve_case)

        debug.info("[time-consuming task] extracting import functions...(pid={0})".format(self.process.UniqueProcessId))
        scan_list = []
        all_mods = list(self.process.get_load_modules())
        if all_mods is not None and len(all_mods) > 0:
            scan_list.append([all_mods[0].DllBase, all_mods[0].SizeOfImage]) # start, size
        # add injected memory regions
        (done,) = self.check_done('injected')
        if int(done):
            self.cur.execute("select start, size from injected where pid = ?", (self.process.UniqueProcessId.v(),))
            records = self.cur.fetchall()
            if records is not None:
                scan_list.extend(records)
        else:
            scan_list.extend(self.detect_code_injections())

        for base_address, size_to_read in scan_list:
            addr_space = self.process.get_process_address_space()
            if not addr_space:
                debug.warning("SectionList_MemorySection_PEInfo_ImportedModules_Module_ImportedFunctions_string: Cannot acquire process AS")
                return False
            data = addr_space.zread(base_address, size_to_read)
            apis = self.enum_apis(all_mods)
            calls_imported = dict(
                    (iat, call)
                    for (_, iat, call) in self.call_scan(addr_space, base_address, data)
                    if call in apis
                    )
            self._vicinity_scan(addr_space,
                    calls_imported, apis, base_address, len(data),
                    forward = True)
            self._vicinity_scan(addr_space,
                    calls_imported, apis, base_address, len(data),
                    forward = False)
            for iat, call in sorted(calls_imported.items()):
                mod_name, func_name = self._original_import(str(apis[call][0].BaseDllName or ''), apis[call][1])
                self.cur.execute("insert into impfunc values (?, ?, ?, ?, ?)", (self.process.UniqueProcessId.v(), iat, call, mod_name, func_name))
                if func_name == '':
                    continue
                if self.util.check_string(func_name, content, condition, preserve_case):
                    result = True

        self.update_done('impfunc')
        return result

    def name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/name'.format(condition))
            return False
        return self.util.check_string(str(self.process.ImageFileName), content, condition, preserve_case)

    def ParentProcessName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/name'.format(condition))
            return False
        if str(self.process.ImageFileName) == "System":
            return self.util.check_string('none', content, condition, preserve_case)
        self.cur.execute("select offset from hidden where pid = ?", (self.process.InheritedFromUniqueProcessId.v(),))
        res = self.cur.fetchone()
        if res is None:
            return False
        pprocess = obj.Object("_EPROCESS", offset = res[0], vm = self.flat_space)
        return self.util.check_string(str(pprocess.ImageFileName), content, condition, preserve_case)

    def path(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/path'.format(condition))
            return False
        path = self.fetchone_from_db('hidden', 'path')
        return self.util.check_string(path, content, condition, preserve_case)

    def arguments(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/arguments'.format(condition))
            return False
        arguments = self.fetchone_from_db('hidden', 'arguments')
        return self.util.check_string(arguments, content, condition, preserve_case)

    # based on malfind.py
    def extract_dllpaths(self):
        debug.info("[time-consuming task] extracting dllpaths from VADs (pid={0})".format(self.process.UniqueProcessId))

        mapped_files = []
        for vad, address_space in self.process.get_vads(vad_filter = self.process._mapped_file_filter):
            if obj.Object("_IMAGE_DOS_HEADER", offset = vad.Start, vm = address_space).e_magic != 0x5A4D:
                continue
            mapped_files.append(str(vad.FileObject.FileName or 'none'))

        records = ((self.process.UniqueProcessId.v(), dllpath) for dllpath in mapped_files)
        self.cur.executemany("insert or ignore into dllpath values (?, ?)", records)
        self.update_done('dllpath')
        return mapped_files

    def DllPath(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/DllPath'.format(condition))
            return False

        (done,) = self.check_done('dllpath')
        if int(done):
            dllpaths = self.fetchall_from_db('dllpath', 'path')
        else:
            dllpaths = self.extract_dllpaths()
        return self.util.check_strings(dllpaths, content, condition, preserve_case)

    # based on handles.py
    def extract_handles(self, is_name=False, is_type=False):
        debug.info("[time-consuming task] extracting handle information...".format(self.process.UniqueProcessId))

        pid = self.process.UniqueProcessId
        handle_list = []
        if self.process.ObjectTable.HandleTableList:
            for handle in self.process.ObjectTable.handles():

                if not handle.is_valid():
                    continue

                name = ""
                object_type = handle.get_object_type()
                if object_type == "File":
                    file_obj = handle.dereference_as("_FILE_OBJECT")
                    name = str(file_obj.file_name_with_device())
                elif object_type == "Key":
                    key_obj = handle.dereference_as("_CM_KEY_BODY")
                    name = key_obj.full_key_name()
                elif object_type == "Process":
                    proc_obj = handle.dereference_as("_EPROCESS")
                    name = "{0}({1})".format(proc_obj.ImageFileName, proc_obj.UniqueProcessId)
                elif object_type == "Thread":
                    thrd_obj = handle.dereference_as("_ETHREAD")
                    name = "TID {0} PID {1}".format(thrd_obj.Cid.UniqueThread, thrd_obj.Cid.UniqueProcess)
                elif handle.NameInfo.Name == None:
                    name = ''
                else:
                    name = str(handle.NameInfo.Name)

                handle_list.append((int(pid), object_type, name))

            records = list(set(handle_list))
            self.cur.executemany("insert or ignore into handles values (?, ?, ?)", records)

            self.update_done('handles')
            if is_name:
                return [record[2] for record in records]
            elif is_type:
                return [record[1] for record in records]

        return None

    def HandleList_Handle_Name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/HandleList/Handle/Name'.format(condition))
            return False

        (done,) = self.check_done('handles')
        if int(done):
            names = self.fetchall_from_db('handles', 'name')
        else:
            names = self.extract_handles(is_name=True)
            if names is None:
                debug.warning('cannot get handles (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(names, content, condition, preserve_case)

    def HandleList_Handle_Type(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/HandleList/Handle/Type'.format(condition))
            return False

        (done,) = self.check_done('handles')
        if int(done):
            types = self.fetchall_from_db('handles', 'type')
        else:
            types = self.extract_handles(is_type=True)
            if types is None:
                debug.warning('cannot get handles (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(types, content, condition, preserve_case)

    def extract_netinfo(self, is_protocol=False, is_laddr=False, is_lport=False, is_raddr=False, is_rport=False, is_state=False):
        debug.info("[time-consuming task] extracting network information...")

        net_list = []
        for net_object, proto, laddr, lport, raddr, rport, state in netscan.Netscan.calculate(self):
            if proto.find("UDP") == -1:
                net_list.append((net_object.Owner.UniqueProcessId.v(), proto, str(laddr), int(lport), str(raddr), int(rport), str(state)))
            else:
                net_list.append((net_object.Owner.UniqueProcessId.v(), proto, str(laddr), int(lport), str(raddr), 0, str(state))) # changed rport (from "*" to 0) in UDP entry

        records = list(set(net_list))
        self.cur.executemany("insert or ignore into netinfo values (?, ?, ?, ?, ?, ?, ?)", records)

        self.update_all_done('netinfo')
        if is_protocol:
            return [record[1] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_laddr:
            return [record[2] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_lport:
            return [record[3] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_raddr:
            return [record[4] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_rport:
            return [record[5] for record in records if self.process.UniqueProcessId.v() == record[0]]
        elif is_state:
            return [record[6] for record in records if self.process.UniqueProcessId.v() == record[0]]

        return None

    def PortList_PortItem_localPort(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localPort'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            lports = self.fetchall_from_db('netinfo', 'lport')
        else:
            lports = self.extract_netinfo(is_lport=True)
            if lports is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_integers(lports, content, condition, preserve_case)

    def PortList_PortItem_remotePort(self, content, condition, preserve_case):
        if not self.util.is_condition_integer(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localPort'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            rports = self.fetchall_from_db('netinfo', 'rport')
        else:
            rports = self.extract_netinfo(is_rport=True)
            if rports is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_integers(rports, content, condition, preserve_case)

    def PortList_PortItem_localIP(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/localIP'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            laddrs = self.fetchall_from_db('netinfo', 'laddr')
        else:
            laddrs = self.extract_netinfo(is_laddr=True)
            if laddrs is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(laddrs, content, condition, preserve_case)

    def PortList_PortItem_remoteIP(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ProcessItem/PortList/PortItem/remoteIP'.format(condition))
            return False

        (done,) = self.check_done('netinfo')
        if int(done):
            raddrs = self.fetchall_from_db('netinfo', 'raddr')
        else:
            raddrs = self.extract_netinfo(is_raddr=True)
            if raddrs is None:
                debug.warning('cannot get netinfo (pid = {0})'.format(self.process.UniqueProcessId))
                return False
        return self.util.check_strings(raddrs, content, condition, preserve_case)

    def hidden(self, content, condition, preserve_case):
        if not self.util.is_condition_bool(condition):
            debug.error('{0} condition is not supported in ProcessItem/hidden'.format(condition))
            return False

        result = self.fetchone_from_db('hidden', 'result')
        if (result and content.lower() == 'true') or ((not result) and content.lower() == 'false'):
            return True
        else:
            return False

class RegistryItem(hivelist.HiveList, shimcache.ShimCache):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()
        self.reg_path_list = []

    def get_path(self, keypath, key):
        if key.Name != None:
            self.reg_path_list.append('{0}'.format(keypath + "\\" + key.Name))
        for k in rawreg.subkeys(key):
            self.get_path(keypath + "\\" + key.Name, k)
        for v in rawreg.values(key):
            if key.Name != None:
                self.reg_path_list.append('{0}'.format(keypath + "\\" + key.Name + "\\" + v.Name))

    def Path(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in RegistryItem/Path'.format(condition))
            return False

        paths = []
        count = self.util.fetchone_from_db(self.cur, "regpath", "count(*)")
        if count > 0:
            paths = self.util.ufetchall_from_db(self.cur, "regpath", "path")
        else:
            debug.info("[time-consuming task] extracting registry key/value paths...")
            hive_offsets = []
            for hive in hivelist.HiveList.calculate(self):
                if hive.Hive.Signature == 0xbee0bee0 and hive.obj_offset not in hive_offsets:
                    hive_offsets.append(hive.obj_offset)
                    h = hivemod.HiveAddressSpace(self.kernel_space, self._config, hive.obj_offset)
                    #key = rawreg.open_key(rawreg.get_root(h), 'software\\microsoft\\windows\\currentversion\\run'.split('\\')) # <- for test
                    #if key:
                    #    self.get_path('', key)
                    self.get_path('', rawreg.get_root(h))
            paths = list(set(self.reg_path_list))
            self.cur.executemany("insert or ignore into regpath values (?)", [(path, ) for path in paths])
        return self.util.check_strings(paths, content, condition, preserve_case)

    def ShimCache_ExecutablePath(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in RegistryItem/ShimCache/ExecutablePath'.format(condition))
            return False

        paths = []
        count = self.util.fetchone_from_db(self.cur, "shimcache", "count(*)")
        if count > 0:
            paths = self.util.fetchall_from_db(self.cur, "shimcache", "path")
        else:
            debug.info("[time-consuming task] extracting shimcache registry information...")
            records = [(path, modified.v()) for path, modified, updated in shimcache.ShimCache.calculate(self)]
            self.cur.executemany("insert or ignore into shimcache values (?, ?)", records)
            paths = [path for path, modified in records]
        return self.util.check_strings(paths, content, condition, preserve_case)

class ServiceItem(svcscan.SvcScan):
    def __init__(self, cur, _config):
        self.cur = cur
        self._config = _config
        self.kernel_space = utils.load_as(self._config)
        self.flat_space = utils.load_as(self._config, astype = 'physical')
        self.util = ItemUtil()

    def extract_services(self, is_service_name=False, is_display_name=False, is_bin_path=False):
        debug.info("[time-consuming task] extracting service information...")

        records = []
        for rec in svcscan.SvcScan.calculate(self):
            service_name = '{0}'.format(rec.ServiceName.dereference())
            display_name = '{0}'.format(rec.DisplayName.dereference())
            bin_path = '{0}'.format(rec.Binary)
            records.append((service_name, display_name, bin_path))
        self.cur.executemany("insert or ignore into service values (?, ?, ?)", records)

        if is_service_name:
            return [record[0] for record in records]
        elif is_display_name:
            return [record[1] for record in records]
        elif is_bin_path:
            return [record[2] for record in records]

    def name(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/name'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            service_names = self.util.fetchall_from_db(self.cur, "service", "service_name")
        else:
            service_names = self.extract_services(is_service_name=True)
            if service_names is None:
                debug.error('cannot get service information')
        return self.util.check_strings(service_names, content, condition, preserve_case)

    def descriptiveName(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/descriptiveName'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            display_names = self.util.fetchall_from_db(self.cur, "service", "display_name")
        else:
            display_names = self.extract_services(is_display_name=True)
            if display_names is None:
                debug.error('cannot get service information')
        return self.util.check_strings(display_names, content, condition, preserve_case)

    def cmdLine(self, content, condition, preserve_case):
        if not self.util.is_condition_string(condition):
            debug.error('{0} condition is not supported in ServiceItem/cmdLine'.format(condition))
            return False

        count = self.util.fetchone_from_db(self.cur, "service", "count(*)")
        if count > 0:
            cmdlines = self.util.fetchall_from_db(self.cur, "service", "bin_path")
        else:
            cmdlines = self.extract_services(is_bin_path=True)
            if cmdlines is None:
                debug.error('cannot get service information')
        return self.util.check_strings(cmdlines, content, condition, preserve_case)

class IOCParseError(Exception):
    pass

class IOC_Scanner:
    def __init__(self):
        self.iocs = {} # elementTree representing the IOC
        self.ioc_name = {} # guid -> name mapping
        self.level = 1 # xml hierarchical level in the IOC
        self.iocEvalString = '' # AND/OR logic of the IOC evaluation
        self.iocLogicString = '' # AND/OR logic result for display
        self.item_obj = None
        self.display_mode = False
        self.cur = None
        self._config = None
        self.items = {'Process':None, 'Registry':None, 'Service':None}
        self.checked_results = {} # for repeatedly checked Items except ProcessItem

    def __len__(self):
        return len(self.iocs)

    def insert(self, filename):
        errors = []
        if os.path.isfile(filename):
            debug.info('loading IOC from: {0}'.format(filename))
            try:
                self.parse(ioc_api.IOC(filename))
            except ioc_api.IOCParseError,e:
                debug.error('Parse Error [{0}]'.format(e))
        elif os.path.isdir(filename):
            debug.info('loading IOCs from: {0}'.format(filename))
            for fn in glob.glob(filename+os.path.sep+'*.ioc'):
                if not os.path.isfile(fn):
                    continue
                else:
                    try:
                        self.parse(ioc_api.IOC(fn))
                    except ioc_api.IOCParseError,e:
                        debug.error('Parse Error [{0}]'.format(str(e)))
        else:
            pass
        debug.info('Parsed [{0}] IOCs'.format(str(len(self))))
        return errors

    def parse(self, ioc_obj):
        if ioc_obj is None:
            return
        iocid = ioc_obj.root.get('id')
        if iocid in self.iocs:
            debug.error('duplicate IOC UUID [{0}] [shortName: {1}]'.format(iocid, self.ioc_name[iocid]))

        # check items
        try:
            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
        except IndexError, e:
            debug.warning('Could not find criteria nodes for IOC [{0}]. '.format(str(iocid)))
            return
        for document in ioc_logic.xpath('//Context/@document'):
            item_name = document[:-4]
            if not item_name in self.items.keys():
                debug.error('Not supported item = {0} in IOC [{1}]. '.format(document, str(iocid)))
                return

        self.iocs[iocid] = ioc_obj
        return True

    def prepare(self, cur, _config):
        self.cur = cur
        self._config = _config

    def withproc(self):
        for iocid in self.iocs:
            ioc_obj = self.iocs[iocid]
            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
            if len(ioc_logic.xpath('//Context[@document="ProcessItem"]')) > 0:
                return True
        return False

    def check_indicator_item(self, node, is_last_item):
        iocResult = False

        condition = node.get('condition')
        preserve_case = node.get('preserve-case')
        negate = node.get('negate')

        document = node.xpath('Context/@document')[0]
        search = node.xpath('Context/@search')[0]
        content = node.findtext('Content')
        logicOperator = str(node.getparent().get("operator")).lower()

        if negate == 'true':
            item_desc = 'Not ' + search + ' ' + condition + ' ' + content
        else:
            item_desc = search + ' ' + condition + ' ' + content

        if self.display_mode:
            if is_last_item:
                self.iocLogicString += '  '*self.level + item_desc + '\n'
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n' + '  '*self.level + str(logicOperator) + '\n'
            return

        method = '_'.join(search.split('/')[1:])
        item_name = document[:-4] # fetch '*' from '*Item'
        if not item_name in self.items.keys():
            debug.error('{0} not supported in this plugin'.format(document))
        if item_name != 'Process' and self.items[item_name] is None:
            self.items[item_name] = eval('{0}(self.cur, self._config)'.format(document))
        if not method in dir(self.items[item_name]):
            debug.error('{0} not supported in this plugin'.format(search))

        if item_name != 'Process' and search in self.checked_results.keys():
            debug.debug('reusing result for repeated ProcessItem')
            iocResult = self.checked_results[search]
        else:
            iocResult = eval('self.items["{0}"].{1}(r"{2}","{3}","{4}")'.format(item_name, method, content, condition, preserve_case))
            #if negate == 'true' and iocResult == True:
            if negate == 'true':
                iocResult = not iocResult
        if item_name != 'Process' and search not in self.checked_results.keys():
            self.checked_results[search] = iocResult

        if is_last_item:
            self.iocEvalString += ' ' + str(iocResult)
            if iocResult:
                self.iocLogicString += '  '*self.level + colorama.Fore.RED + item_desc + colorama.Fore.RESET + '\n'
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n'
        else:
            self.iocEvalString += ' ' + str(iocResult) + ' ' + str(logicOperator)
            if iocResult:
                self.iocLogicString += '  '*self.level + colorama.Fore.RED + item_desc + colorama.Fore.RESET + '\n' + '  '*self.level + str(logicOperator) + '\n'
            else:
                self.iocLogicString += '  '*self.level + item_desc + '\n' + '  '*self.level + str(logicOperator) + '\n'

    def walk_indicator(self, node):
        expected_tag = 'Indicator'
        if node.tag != expected_tag:
            raise ValueError('node expected tag is [{0}]'.format(expected_tag))

        for chn in node.getchildren():
            chn_id = chn.get('id')

            if chn.tag == 'IndicatorItem':
                if chn == node.getchildren()[-1]:
                    self.check_indicator_item(chn, True)
                else:
                    self.check_indicator_item(chn, False)

            elif chn.tag == 'Indicator':
                operator = chn.get('operator').lower()
                if operator not in ['or', 'and']:
                    raise IOCParseError('Indicator@operator is not AND/OR. [{0}] has [{1}]'.format(chn_id, operator) )

                self.iocEvalString += ' ('
                self.iocLogicString += '  '*self.level + '(\n'
                self.level+=1

                self.walk_indicator(chn)

                self.level-=1
                logicOperator = str(node.getparent().get("operator")).lower()
                if logicOperator == 'none': # maybe top
                    logicOperator = 'or'
                if chn == node.getchildren()[-1]:
                    self.iocLogicString += '  '*self.level + ')\n'
                    self.iocEvalString += ' )'
                else:
                    self.iocLogicString += '  '*self.level + ')\n' + '  '*self.level + str(logicOperator) + '\n'
                    self.iocEvalString += ' )' + ' ' + str(logicOperator)

            else:
                # should never get here
                raise IOCParseError('node is not a Indicator/IndicatorItem')

    def scan(self, process):
        result = ''

        if len(self) < 1:
            debug.error('no iocs available to scan')
            return result

        if process is not None:
            self.items['Process'] = ProcessItem(process, self.cur, self._config)

        for iocid in self.iocs:
            ioc_obj = self.iocs[iocid]
            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
            try:
                tlo = ioc_logic.getchildren()[0]
            except IndexError, e:
                debug.warning('Could not find children for the top level criteria/children nodes for IOC [{0}]'.format(str(iocid)))
                continue

            self.walk_indicator(tlo)
            debug.debug(self.iocEvalString)
            if eval(self.iocEvalString):
                result += ('------------------------------------------------------\n')
                result += ('IOC matched! short_desc="{0}" id={1}\n'.format(ioc_obj.metadata.findtext('.//short_description'), iocid))
                result += ('logic (matched item is red-colored):\n{0}'.format(self.iocLogicString))
            self.iocEvalString=""
            self.iocLogicString=""

        self.items['Process'] = None
        return result

    def display(self):
        self.display_mode = True
        result = ''

        if len(self) < 1:
            debug.error('no iocs to display')
            return result

        for iocid in self.iocs:
            ioc_obj = self.iocs[iocid]
            ioc_logic = ioc_obj.root.xpath('.//criteria')[0]
            try:
                tlo = ioc_logic.getchildren()[0]
            except IndexError, e:
                debug.warning('Could not find children for the top level criteria/children nodes for IOC [{0}]'.format(str(iocid)))
                continue

            self.walk_indicator(tlo)
            result += ('++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n')
            result += ('IOC definition short_desc="{0}" id={1}\n'.format(ioc_obj.metadata.findtext('.//short_description'), iocid))
            result += ('logic:\n{0}'.format(self.iocLogicString))
            self.iocLogicString=""

        return result

class OpenIOC_Scan(psxview.PsXview, taskmods.DllList):
    """Scan OpenIOC 1.1 based indicators"""
    meta_info = commands.Command.meta_info
    meta_info['author'] = 'Takahiro Haruyama'
    meta_info['copyright'] = 'Copyright (c) 2014 Takahiro Haruyama'
    meta_info['license'] = 'GNU General Public License 2.0'
    meta_info['url'] = 'http://takahiroharuyama.github.io/'

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('PID', short_option = 'p', default = None,
                                help = 'Operate on these Process IDs (comma-separated)',
                                action = 'store', type = 'str')
        self._config.add_option('ioc_dir', short_option = 'i', default = None,
                               help = 'Location of IOCs directory',
                               action = 'store', type = 'str')
        self._config.add_option('show', short_option = 's', default = False,
                               help = 'Display IOC definition only',
                               action = 'store_true')
        self._config.add_option('cache_path', short_option = 'c', default = None,
                               help = 'Specify the cache folder path of analysis result',
                               action = 'store', type = 'str')
        self.db = None
        self.cur = None
        self.total_secs = 0

    def filter_tasks(self, tasks):
        if self._config.PID is None:
            return tasks

        try:
            pidlist = [int(p) for p in self._config.PID.split(',')]
        except ValueError:
            debug.error("Invalid PID {0}".format(self._config.PID))

        return [t for t in tasks if t.UniqueProcessId in pidlist]

    def clear_tables(self):
        debug.info("Loaded DB version is different from that of the script. Clearing the tables...")
        self.cur.execute("drop table if exists version")
        self.cur.execute("drop table if exists done")
        self.cur.execute("drop table if exists injected")
        self.cur.execute("drop table if exists strings")
        self.cur.execute("drop table if exists vaddump")
        self.cur.execute("drop table if exists impfunc")
        self.cur.execute("drop table if exists handles")
        self.cur.execute("drop table if exists netinfo")
        self.cur.execute("drop table if exists hidden")
        self.cur.execute("drop table if exists dllpath")
        self.cur.execute("drop table if exists regpath")
        self.cur.execute("drop table if exists shimcache")
        self.cur.execute("drop table if exists service")

    def make_tables(self):
        debug.info("Making new DB tables...")
        self.cur.execute("create table if not exists version(version unique)")
        self.cur.execute("insert into version values(?)", (g_version,))
        self.cur.execute("create table if not exists done(pid unique, injected, strings, vaddump, impfunc, handles, netinfo, dllpath)")
        self.cur.execute("create table if not exists injected(pid, start, size)")
        self.cur.execute("create table if not exists strings(pid, string)")
        self.cur.execute("create table if not exists vaddump(pid unique, size)")
        self.cur.execute("create table if not exists impfunc(pid, iat, call, mod_name, func_name)")
        self.cur.execute("create table if not exists handles(pid, type, name)")
        self.cur.execute("create table if not exists netinfo(pid, protocol, laddr, lport, raddr, rport, state)")
        self.cur.execute("create table if not exists hidden(pid unique, result, offset, path, arguments)")
        self.cur.execute("create table if not exists dllpath(pid, path)")
        self.cur.execute("create table if not exists regpath(path unique)")
        self.cur.execute("create table if not exists shimcache(path, modified)")
        self.cur.execute("create table if not exists service(service_name, display_name, bin_path)")

    def init_db(self):
        global g_cache_path
        image_url = self._config.opts["location"]
        image_path = urllib.url2pathname(image_url.split('///')[1])

        if self._config.cache_path is None:
            g_cache_path = os.path.join(os.path.dirname(image_path), os.path.basename(image_path).split('.')[0] + '_cache')
            if not os.path.exists(g_cache_path):
                os.mkdir(g_cache_path)
        else:
            g_cache_path = self._config.cache_path
        self.db = sqlite3.connect(os.path.join(g_cache_path, os.path.basename(image_path).split('.')[0] + '.db'))
        self.cur = self.db.cursor()

        # version is null or not matched, make new tables
        self.cur.execute("select * from sqlite_master where type='table'")
        if self.cur.fetchone() == None:
            self.make_tables()
        else:
            self.cur.execute("select * from version")
            db_version = self.cur.fetchone()[0]
            if db_version == g_version:
                debug.info("Results in existing database loaded")
            else:
                self.clear_tables()
                self.make_tables()

    def parse_cmdline(self, process):
        debug.debug(process.ImageFileName)
        if str(process.ImageFileName) != "System":
            cmdline = str(process.Peb.ProcessParameters.CommandLine).lower()
            debug.debug('name="{0}", cmdline="{1}" (pid{2})'.format(process.ImageFileName, cmdline or None, process.UniqueProcessId))
            if cmdline is not None:
                name_idx = cmdline.find(str(process.ImageFileName).lower())
                debug.debug('name_idx={0}'.format(name_idx))
                if name_idx != -1:
                    exe_idx = cmdline.find('.exe', name_idx)
                    debug.debug("name='{0}', path='{1}', arg='{2}' (pid{3})".format(process.ImageFileName, cmdline[:exe_idx+4].strip('" '), cmdline[exe_idx+4:].strip('" '), process.UniqueProcessId))
                    return cmdline[:exe_idx+4].strip('" '), cmdline[exe_idx+4:].strip('" ')
        return 'none', 'none'

    # based on psxview.py
    def extract_all_active_procs(self):
        kernel_space = utils.load_as(self._config)
        flat_space = utils.load_as(self._config, astype = 'physical')
        self.cur.execute("select count(*) from hidden")
        carved = self.cur.fetchone()[0]

        procs = []
        if carved > 0:
            self.cur.execute("select offset from hidden")
            return [self.virtual_process_from_physical_offset(kernel_space, record[0]) for record in self.cur.fetchall()]
            #return [obj.Object("_EPROCESS", offset = record[0], vm = flat_space) for record in self.cur.fetchall()]
            #return [obj.Object("_EPROCESS", offset = record[0], vm = kernel_space) for record in self.cur.fetchall()]
        else:
            debug.info("[time-consuming task] extracting all processes including hidden ones...")
            all_tasks = list(tasks.pslist(kernel_space))
            ps_sources = {}
            ps_sources['pslist'] = self.check_pslist(all_tasks)
            ps_sources['psscan'] = self.check_psscan()
            #ps_sources['thrdproc'] = self.check_thrdproc(kernel_space)
            ps_sources['pspcid'] = self.check_pspcid(kernel_space)

            seen_offsets = []
            records = []
            procs = []
            for source in ps_sources.values():
                for offset in source.keys():
                    if offset not in seen_offsets:
                        seen_offsets.append(offset)
                        if source[offset].ExitTime != 0: # exclude dead process even if it is included in process list
                        #if (source[offset].ExitTime != 0) and (not ps_sources['pslist'].has_key(offset)): # exclude dead process not included in process list <- cannot resolve from ethread!
                            continue
                        result = not (ps_sources['pslist'].has_key(offset) and ps_sources['psscan'].has_key(offset) and ps_sources['pspcid'].has_key(offset))
                        path, arguments = self.parse_cmdline(source[offset])
                        records.append((source[offset].UniqueProcessId.v(), bool(result), offset, path, arguments))
                        procs.append(source[offset])
            self.cur.executemany("insert or ignore into hidden values (?, ?, ?, ?, ?)", records)
            return procs

    def calculate(self):
        # load IOCs
        scanner = IOC_Scanner()
        if self._config.ioc_dir is None:
            debug.error("You should specify IOCs directory")
        scanner.insert(self._config.ioc_dir)

        # display mode
        if self._config.show:
            definitions = scanner.display()
            yield definitions
        else:
            self.init_db()
            scanner.prepare(self.cur, self._config)
            if scanner.withproc():
                procs = self.extract_all_active_procs()
                # pre-generated process entries in db for all updated tasks (e.g., netinfo)
                for process in self.filter_tasks(procs):
                    self.cur.execute("insert or ignore into done values(?, ?, ?, ?, ?, ?, ?, ?)", (process.UniqueProcessId.v(), False, False, False, False, False, False, False))
                for process in self.filter_tasks(procs):
                    with Timer() as t:
                        result = scanner.scan(process)
                    debug.debug("=> elasped scan: {0} s (pid{1})".format(t.secs, process.UniqueProcessId))
                    self.total_secs += t.secs
                    if result != '':
                        yield process, result
            else:
                with Timer() as t:
                    result = scanner.scan(None)
                debug.debug("=> elasped scan: {0} s".format(t.secs))
                self.total_secs += t.secs
                if result != '':
                    yield None, result

    def render_text(self, outfd, data):
        if self._config.show:
            for definitions in data:
                outfd.write('\n' + definitions)
        else:
            for process, ioc_result in data:
                outfd.write('***************************************************************\n')
                outfd.write(ioc_result)
                if process is not None:
                    outfd.write("Note: ProcessItem was evaluated only in {0} (Pid={1})\n".format(process.ImageFileName, process.UniqueProcessId))

            self.db.commit()
            self.cur.close()
            outfd.write('***************************************************************\n')
            debug.debug("=> elasped scan total: {0} s".format(self.total_secs))

