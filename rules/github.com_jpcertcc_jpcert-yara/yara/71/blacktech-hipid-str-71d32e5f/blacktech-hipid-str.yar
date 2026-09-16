rule BlackTech_Hipid_str {
     meta:
        description = "Multi-architecture (ARM or x64) backdoor in BlackTech"
        author = "JPCERT/CC Incident Response Group"
        hash = "3d18bb8b9a5af20ab10441c8cd40feff0aabdd3f4c669ad40111e3aa5e8c54b8"
        hash = "9603b62268c2bbb06da5c99572c3dc2ec988c49c86db2abc391acf53c1cccceb"

     strings:
        $msg1 = "[+] my_dns_query failed." ascii fullword
        $msg2 = "[+] my_dns_query success." ascii fullword
        $msg3 = "[+] connect to %s:%d failed." ascii fullword
        $msg4 = "[+] connect to %s:%d success." ascii fullword
        $msg5 = "cmd: %s" ascii fullword
        $msg6 = "path: %s" ascii fullword
        $msg7 = "has address" ascii fullword
        $msg8 = "host %s" ascii fullword
        $msg9 = {84 D2 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 72 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 77 (74 ?? |0F ?? ?? ?? 00 00) 80 FA 65 (74 ?? |0F ?? ?? ?? 00 00)}
        $func1 = "exec_cmd_send_xor" ascii fullword
        $func2 = "exec_cmd" ascii fullword
        $func3 = "rc4_init" ascii fullword
        $func4 = "my_dns_query" ascii fullword
        $func5 = "rc4_key" ascii fullword
        $func6 = "daemon_init" ascii fullword
        $key1 = "pASSword699" ascii fullword
        $key2 = "345asdflkasduf" ascii fullword

     condition:
       uint32(0) == 0x464C457F and
       (4 of ($msg*) or 4 of ($func*) or 1 of ($key*))
}