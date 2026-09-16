rule _Virus_Hijack_Gen_Trojan_ShellObject_m8Z_a4IIY9p_3_VirusShareTro_465 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.m8Z@a4IIY9p_3.vir, VirusShareTrojanInjectNET40_1.vir, VirusShareTrojanInjectNET40_3.vir, VirusShareTrojanInjectNET40_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2b2d5f499448f080739b596ecd788e8936d72e82b33370f62e1603c9d7f2220"
    hash2       = "7e9ba5d23a8857c2804f337cf949f2d7e79cf0a458040825aea3b3a16fd02471"
    hash3       = "8deda209aacde6403f811ed341ec84abdeb0f8a88330a0268209277b4f48d451"
    hash4       = "f8f168e1fcbf60a53d9bc3bd33b60394c2976c3b2f0e5ee7e4d7b14a8730ac85"

  strings:
    $s1 = "DEBUG: Executable base address: 0x" fullword wide
    $s2 = "Started 'svchost.exe' in a suspended state with PID {0}. Success: {1}." fullword wide
    $s3 = "Triggered payload. Success: {0}. Check your listener!" fullword wide
    $s4 = "Got executable entrypoint address: 0x" fullword wide
    $s5 = "Overwrote entrypoint with payload. Success: {0}." fullword wide
    $s6 = "Got process information and located PEB address of process at {0}. Success: {1}." fullword wide
    $s7 = "DEBUG: e_lfanew offset: 0x" fullword wide
    $s8 = "DEBUG: RVA offset: 0x" fullword wide
    $s9 = "DEBUG: RVA value: 0x" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}