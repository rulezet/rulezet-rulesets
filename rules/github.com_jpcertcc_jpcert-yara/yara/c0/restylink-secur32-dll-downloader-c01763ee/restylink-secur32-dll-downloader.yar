rule restylink_Secur32_dll_downloader {
    meta:
        description = "Hunting no stripped Binaries by AutoYara4ELFsig JPCERT/CC"
        author = "AutoYara4ELFsig"
        rule_usage = "Hunting"
        hash = "107426B7B30D613E694F9153B415037C4E8194B7E7C96F0760EB59DE8F349809"
    
    strings:
        
        $func0 = { 41 B8 00 20 00 00 48 8B D3 49 8B CE FF D6 B9 64 00 00 00 FF D7 48 81 C3 00 20 00 00 }

        
        $func1 = { 44 8B C7 BB A3 00 00 00 0F 1F 80 00 00 00 00 FF C0 25 FF 00 00 80 7D 09 FF C8 0D 00 FF FF FF FF C0 48 63 C8 }

        
        $func2 = { 6A 23 67 68 73 6A 40 25  64 68 67 23 38 37 75 2A 23 52 59 43 49 48 66 76  64 20 29 37 }

        
        $func3 = { 61 62 63 2E 6D 62 75 73 61 62 63 2E 63 6F 6D 00}

    condition:
        (uint16(0) == 0x5A4D)
        and (filesize < 1MB)
        and ( 1 of ($func*) )
}