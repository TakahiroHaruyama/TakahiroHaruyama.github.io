# plugx_config_dumper_IDA.py - IDAPython script dumping/parsing PlugX encrypted config included in .idb file
# Copyright (c) 2014 Takahiro Haruyama
#
# This script can be used for PlugX specimens including config whose size is 0x72C/0x76C/0xDF0/0x7AC/0x840
# How to use:
# 1. find the function for decoding obfuscated strings and specify it as "decode_function_name" (right below)
# 2. Run this script
# 3. Check the result in Output window
# For more detail, check this blog post: http://takahiroharuyama.github.io/

decode_function_name = 'func_decode_string'

size_list = [0x72C, 0x76C, 0xDF0, 0x7AC, 0x840]

def parse_72C_config(ea):
    num_of_servers = 4
    C2_struct_len = 0xC4
    out = ''

    msec_for_WaitForSingleObject = Dword(ea + 8)
    out += 'msec_for_WaitForSingleObject: %d\n' % msec_for_WaitForSingleObject

    for entry in range(num_of_servers):
        offset = ea + 0xC + entry * C2_struct_len
        protocol_flag = Word(offset)
        port = Word(offset + 2)
        hostname = GetString(offset + 4, -1, ASCSTR_C)
        username = GetString(offset + 0x44, -1, ASCSTR_C)
        password = GetString(offset + 0x84, -1, ASCSTR_C)
        out += "C2 (or Proxy) server entry %d: connection type (1=TCP&direct, 2=none, 3=TCP&proxy, 4=TCP&proxy_with_auth, 5=HTTP&proxy, 6=HTTP&direct) = %d, hostname = %s, port = %d, proxy username = %s, proxy pasword = %s\n" % (entry, protocol_flag, hostname, port, username, password)

    service_name = GetString(ea + 0x6AC, -1, ASCSTR_C)
    out += "service or dll name: %s\n" % (service_name)
    service_desc = GetString(ea + 0x6EC, -1, ASCSTR_C)
    out += "service description: %s\n" % (service_desc)

    return out

def parse_76C_config(ea):
    num_of_servers = 4
    C2_struct_len = 0xC4
    out = ''

    msec_for_WaitForSingleObject = Dword(ea + 8)
    out += 'msec_for_WaitForSingleObject: %d\n' % msec_for_WaitForSingleObject

    for entry in range(num_of_servers):
        offset = ea + 0xC + entry * C2_struct_len
        protocol_flag = Word(offset)
        port = Word(offset + 2)
        hostname = GetString(offset + 4, -1, ASCSTR_C)
        username = GetString(offset + 0x44, -1, ASCSTR_C)
        password = GetString(offset + 0x84, -1, ASCSTR_C)
        out += "C2 (or Proxy) server entry %d: connection type (1=TCP&direct, 2=none, 3=TCP&proxy, 4=TCP&proxy_with_auth, 5=HTTP&proxy, 6=HTTP&direct) = %d, hostname = %s, port = %d, proxy username = %s, proxy pasword = %s\n" % (entry, protocol_flag, hostname, port, username, password)

    service_name = GetString(ea + 0x6AC, -1, ASCSTR_C)
    out += "service or dll name: %s\n" % (service_name)
    service_desc = GetString(ea + 0x6EC, -1, ASCSTR_C)
    out += "service description: %s\n" % (service_desc)
    display_name = GetString(ea + 0x72C, -1, ASCSTR_C)
    out += "service display name: %s\n" % (display_name)

    return out

def parse_DF0_config(ea):
    num_of_servers = 8
    C2_struct_len = 0xC4
    out = ''

    for entry in range(num_of_servers):
        offset = ea + 0x2C0 + entry * C2_struct_len
        protocol_flag = Word(offset)
        port = Word(offset + 2)
        hostname = GetString(offset + 4, -1, ASCSTR_C)
        username = GetString(offset + 0x44, -1, ASCSTR_C)
        password = GetString(offset + 0x84, -1, ASCSTR_C)
        if hostname.find("HTTP://") == 0:
            out += "C2 (or Proxy or C2SettingURL) server entry %d: C2 Setting URL = %s, proxy username = %s, proxy pasword = %s\n" % (entry, hostname, username, password)
        else:
            out += "C2 (or Proxy or C2SettingURL) server entry %d: connection type (1=TCP&direct, 2=none, 3=TCP&proxy, 4=TCP&proxy_with_auth, 5=HTTP&proxy, 6=HTTP&direct) = %d, hostname = %s, port = %d, proxy username = %s, proxy pasword = %s\n" % (entry, protocol_flag, hostname, port, username, password)

    magic_word = GetString(ea + 0xC70, -1, ASCSTR_UNICODE)
    out += "magic word for sending data: %s\n" % (magic_word)
    service_name = GetString(ea + 0xCF0, -1, ASCSTR_UNICODE)
    out += "service or dll name: %s\n" % (service_name)
    service_desc = GetString(ea + 0xD70, -1, ASCSTR_UNICODE)
    out += "service description: %s\n" % (service_desc)

    return out

def parse_7AC_config(ea):
    num_of_servers = 4
    C2_struct_len = 0xC4
    out = ''

    msec_for_WaitForSingleObject = Dword(ea + 8)
    out += 'msec_for_WaitForSingleObject: %d\n' % msec_for_WaitForSingleObject

    for entry in range(num_of_servers):
        offset = ea + 0xC + entry * C2_struct_len
        protocol_flag = Word(offset)
        port = Word(offset + 2)
        hostname = GetString(offset + 4, -1, ASCSTR_C)
        username = GetString(offset + 0x44, -1, ASCSTR_C)
        password = GetString(offset + 0x84, -1, ASCSTR_C)
        out += "C2 (or Proxy) server entry %d: connection type (1=TCP&direct, 2=none, 3=TCP&proxy, 4=TCP&proxy_with_auth, 5=HTTP&proxy, 6=HTTP&direct) = %d, hostname = %s, port = %d, proxy username = %s, proxy pasword = %s\n" % (entry, protocol_flag, hostname, port, username, password)

    service_name = GetString(ea + 0x6AC, -1, ASCSTR_UNICODE)
    out += "service or dll name: %s\n" % (service_name)
    service_desc = GetString(ea + 0x6EC, -1, ASCSTR_UNICODE)
    out += "service description: %s\n" % (service_desc)
    display_name = GetString(ea + 0x72C, -1, ASCSTR_UNICODE)
    out += "service display name: %s\n" % (display_name)
    unk = GetString(ea + 0x76C, -1, ASCSTR_UNICODE)
    out += "unknown string: %s\n" % (unk)

    return out

def parse_840_config(ea):
    num_of_servers = 4
    C2_struct_len = 0xC4
    out = ''

    msec_for_WaitForSingleObject = Dword(ea + 8)
    out += 'msec_for_WaitForSingleObject: %d\n' % msec_for_WaitForSingleObject

    for entry in range(num_of_servers):
        offset = ea + 0x20 + entry * C2_struct_len
        protocol_flag = Word(offset)
        port = Word(offset + 2)
        hostname = GetString(offset + 4, -1, ASCSTR_C)
        username = GetString(offset + 0x44, -1, ASCSTR_C)
        password = GetString(offset + 0x84, -1, ASCSTR_C)
        out += "C2 (or Proxy) server entry %d: connection type (1=TCP&direct, 2=none, 3=TCP&proxy, 4=TCP&proxy_with_auth, 5=HTTP&proxy, 6=HTTP&direct) = %d, hostname = %s, port = %d, proxy username = %s, proxy pasword = %s\n" % (entry, protocol_flag, hostname, port, username, password)

    online_pass = GetString(ea + 0x6C0, -1, ASCSTR_UNICODE)
    out += "online pass: %s\n" % (online_pass)
    service_name = GetString(ea + 0x740, -1, ASCSTR_UNICODE)
    out += "service or dll name: %s\n" % (service_name)
    service_desc = GetString(ea + 0x7C0, -1, ASCSTR_UNICODE)
    out += "service description: %s\n" % (service_desc)

    return out

def parse_config(ea, size):
    if size == 0x76C:
        return parse_76C_config(ea)
    elif size == 0xDF0:
        return parse_DF0_config(ea)
    elif size == 0x72C:
        return parse_72C_config(ea)
    elif size == 0x7AC:
        return parse_7AC_config(ea)
    elif size == 0x840:
        return parse_840_config(ea)
    else:
        return 'unknown size: 0x%x\n' % size

def decrypt_config(config_ea, dst_ea, key, size):
    v4 = key
    v5 = key
    v6 = key

    for offset in range(0, size):
        v4 = 0xFFFFFFFF & ((0xFFFFFFFF & (v4 + (0xFFFFFFFF & (v4 >> 3)))) + 3)
        v5 = 0xFFFFFFFF & ((0xFFFFFFFF & (v5 + (0xFFFFFFFF & (v5 >> 5)))) + 5)
        key = 0xFFFFFFFF & ((0xFFFFFFFF & (key -9)) - (0xFFFFFFFF & (key << 9)))

        value = Byte(config_ea + offset) ^ (0xFF & ((0xFF & ((0xFF & (key -7)) - (0xFF & (v6 << 7)))) + (0xFF & v6) + (0xFF & v5) + (0xFF & v4)))
        PatchByte(dst_ea + offset, value)
        v6 = 0xFFFFFFFF & ((0xFFFFFFFF & (v6 - 7)) - (0xFFFFFFFF & (v6 << 7)))

def decode(ea_encoded, data_len, key, ea_decoded):
    key2 = key
    key3 = key
    key4 = key
    decoded_str = []
    for offset in range(0, data_len):
        key2 = 0xFFFFFFFF & (key2 + (-3 - 8 * key2))
        value2 = 0xFFFFFFFF & (-5 - 32 * key3 + key3)
        value3 = 0xFFFFFFFF & (129 * key + 7)
        key4 = 0xFFFFFFFF & (513 * key4 + 9)
        key = value3
        value3 = 0xFFFFFFFF & (value3 + key4)
        key3 = value2

        decoded_byte = Byte(ea_encoded + offset) ^ (0xFF & (key2 + value2 + value3))
        PatchByte(ea_decoded + offset, decoded_byte)

    if Byte(ea_decoded + 1) == 0 and data_len != 1:
        idaapi.make_ascii_string(ea_decoded, data_len, ASCSTR_UNICODE)
    else:
        idaapi.make_ascii_string(ea_decoded, data_len, ASCSTR_C)

    if Byte(ea_decoded + 1) == 0 and data_len != 1:
        result = GetString(ea_decoded, -1, ASCSTR_UNICODE)
    else:
        result = GetString(ea_decoded, -1, ASCSTR_C)

    return result

def search_func_decoding(decoded_str):
    image_base = idaapi.get_imagebase()
    print 'searching: decode "%s"' % decoded_str
    ea = FindText(image_base, SEARCH_DOWN|SEARCH_CASE, 0, 0, 'decode "%s"' % decoded_str)
    if ea == BADADDR:
        return BADADDR
    fn_start = GetFunctionAttr(ea, FUNCATTR_START)
    print 'func decoding %s at %x' % (decoded_str, fn_start)
    return fn_start

def dump_config(enc_config_ea, dec_config_ea, size):
    print 'enc_config_ea=0x%x, dec_config_ea=0x%x, size=0x%x' % (enc_config_ea, dec_config_ea, size)
    MakeName(enc_config_ea, 'encrypted_config')
    MakeName(dec_config_ea, 'decrypted_config')
    key = Dword(enc_config_ea)
    if key == 0x58585858:
        print 'This is DEMO version without config'
        return
    decrypt_config(enc_config_ea, dec_config_ea, key, size)
    if Dword(dec_config_ea + 4) == key:
        print 'config decrypted'
        config_bin = GetManyBytes(dec_config_ea, size)
        wf = open(GetIdbDir() + '\\config.bin', 'wb')
        wf.write(config_bin)
        wf.close()
        print 'config.bin saved: %s' % GetIdbDir() + '\\config.bin'
        config_parsed_out = parse_config(dec_config_ea, size)
        wf = open(GetIdbDir() + '\\config.txt', 'w')
        wf.write(config_parsed_out)
        wf.close()
        print 'config.txt saved: %s' % GetIdbDir() + '\\config.txt'
    else:
        print 'config CANNOT be decrypted. You may need another algorithm...'
    return

def search_args(ea, num_of_args, direction):
    arg_cnt = 0
    arg_list = []
    while ea != BADADDR:
        if GetMnem(ea) == 'push':
            arg_list.append(GetOperandValue(ea, 0))
            arg_cnt += 1
            if arg_cnt == num_of_args:
                break
        if direction == 'up':
            ea = FindCode(ea, SEARCH_UP)
        else:
            ea = FindCode(ea, SEARCH_DOWN)
    return arg_list

def main():
    decode_func = LocByName(decode_function_name)
    if decode_func == BADADDR:
        print '%s: no such name' % decode_function_name
        return
    refs = CodeRefsTo(decode_func, False)

    for ref in refs:
        if GetMnem(ref) == 'call':
            call_ea = ref
            arg_list = []
            arg_cnt = 0
            ref = FindCode(ref, SEARCH_UP)
            while ref != BADADDR:
                if GetMnem(ref) == 'push' or (GetMnem(ref) == 'mov' and GetOpType(ref, 0) == o_reg and GetOpType(ref, 1) != o_reg):
                    break
                ref = FindCode(ref, SEARCH_UP)

            if GetMnem(ref) == 'push': # 0x72c/0x76c/0xdf0/0x840
                arg_list = search_args(ref, 4, "up")
            #elif GetMnem(ref) == 'mov': # 0x7ac
            else: # 0x7ac
                data_len = key = ea_decoded = ea_encoded = 0
                while ref != BADADDR:
                    if GetMnem(ref) == 'mov':
                        if GetOpnd(ref, 0) == 'edi' and GetOpType(ref, 1) == o_imm:
                            if data_len == 0:
                                data_len = GetOperandValue(ref, 1)
                                arg_cnt += 1
                        elif GetOpnd(ref, 0) == 'ecx' and GetOpType(ref, 1) == o_imm:
                            if key == 0:
                                key = GetOperandValue(ref, 1)
                                arg_cnt += 1
                        #elif GetOpnd(ref, 0) == 'eax' and (GetOpType(ref, 1) == o_far or GetOpType(ref, 1) == o_near):
                        elif GetOpnd(ref, 0) == 'eax':
                            if ea_decoded == 0:
                                ea_decoded = GetOperandValue(ref, 1)
                                arg_cnt += 1
                    elif GetMnem(ref) == 'push':
                        if ea_encoded == 0:
                            ea_encoded = GetOperandValue(ref, 0)
                            arg_cnt += 1
                    if arg_cnt == 4:
                        arg_list = ea_encoded, data_len, key, ea_decoded
                        break
                    ref = FindCode(ref, SEARCH_UP)

            print "%0x" % call_ea
            print arg_list
            result = decode(*arg_list)
            print 'decoding "%s" at 0x%x' % (result, call_ea)
            MakeComm(call_ea, 'decode "%s"' % result)
    Refresh()
    #AnalyzeArea(MinEA(), MaxEA())
    print 'strings de-obfuscated'

    enc_config_ea = dec_config_ea = 0
    for size in size_list:
        print 'determining config size... (0x%x)' % size
        if size == 0x72C or size == 0x76C or size == 0x7AC or size == 0x840:
            fn_start = search_func_decoding("XXXXXXXX")
            if fn_start == BADADDR:
                print 'config decryption routine for 0x%x NOT found' % size
                continue
            if size == 0x72C:
                ea = FindBinary(fn_start, SEARCH_DOWN, "68 2C 07 00 00")
            elif size == 0x76C:
                ea = FindBinary(fn_start, SEARCH_DOWN, "68 6C 07 00 00")
            elif size == 0x7AC:
                ea = FindBinary(fn_start, SEARCH_DOWN, "68 AC 07 00 00")
            elif size == 0x840:
                ea = FindBinary(fn_start, SEARCH_DOWN, "68 40 08 00 00")
            if ea == BADADDR:
                print '"push 0x%x" NOT found' % size
                continue
            size, enc_config_ea, dec_config_ea = search_args(ea, 3, "down")
            dump_config(enc_config_ea, dec_config_ea, size)
            return
        elif size == 0xDF0:
            fn_start = search_func_decoding("DEMO")
            if fn_start == BADADDR:
                print 'set_defaultConfigValues routine for 0x%x NOT found' % size
                continue
            (ref,) = CodeRefsTo(fn_start, False)
            fn_start = GetFunctionAttr(ref, FUNCATTR_START)
            ea = FindBinary(fn_start, SEARCH_DOWN, "68 F0 0D 00 00")
            if ea == BADADDR:
                print '"push 0x%x" NOT found' % size
                continue
            ea = FindCode(ea, SEARCH_DOWN)
            enc_config_ea = GetOperandValue(ea, 0)
            fn_start = search_func_decoding("CONFIG-ERROR")
            if fn_start == BADADDR:
                print 'config decryption routine for 0x%x NOT found' % size
                continue
            ea = FindBinary(fn_start, SEARCH_DOWN, "68 F0 0D 00 00")
            ea = FindCode(ea, SEARCH_DOWN)
            dec_config_ea = GetOperandValue(ea, 0)
            dump_config(enc_config_ea, dec_config_ea, size)
            return

    print 'config NOT found'

if __name__ == '__main__':
    main()