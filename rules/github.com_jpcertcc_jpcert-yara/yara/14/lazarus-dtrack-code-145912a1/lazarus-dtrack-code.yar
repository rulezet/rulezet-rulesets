rule Lazarus_Dtrack_code {
     meta:
        description = "Dtrack malware in Lazarus"
        author = "JPCERT/CC Incident Response Group"
        hash = "2bcb693698c84b7613a8bde65729a51fcb175b04f5ff672811941f75a0095ed4"
        hash = "467893f5e343563ed7c46a553953de751405828061811c7a13dbc0ced81648bb"

     strings:
        $rc4key1 = "xwqmxykgy0s4"
        $rc4key2 = "hufkcohxyjrm"
        $rc4key3 = "fm5hkbfxyhd4"
        $rc4key4 = "ihy3ggfgyohx"
        $rc4key5 = "fwpbqyhcyf2k"
        $rc4key6 = "rcmgmg3ny3pa"
        $rc4key7 = "a30gjwdcypey"
        $zippass1 = "dkwero38oerA^t@#"
        $zippass2 = "z0r0f1@123"
        $str1 = "Using Proxy"
        $str2 = "Preconfig"
        $str3 = "%02d.%02d.%04d - %02d:%02d:%02d:%03d :"
        $str4 = "%02X:%02X:%02X:%02X:%02X:%02X"
        $str5 = "%s\\%c.tmp"
        $code = { 81 ?? EB 03 00 00 89 ?? ?? ?? FF FF 83 ?? ?? ?? FF FF 14 0F 87 EA 00 00 00 }

     condition:
       uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550 and
       (1 of ($rc4key*) or 1 of ($zippass*) or (3 of  ($str*) and $code))
}