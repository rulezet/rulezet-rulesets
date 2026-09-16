rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104_1_Virus_Hija_346 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash2       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash3       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash4       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash5       = "9dd481aae9a5d9bb4492b165f159bb9b6e7d7a9fc94fa24820790c8c1d87ee10"
    hash6       = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash7       = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "   -m      Creates a mirror dump, which is a consistent view of kernel memory" fullword ascii
    $s2  = "   -mp     Specifies a single process whose user mode memory contents should be" fullword ascii
    $s3  = "           0001 - process private,  0002 - mapped file,   0004 - shared section" fullword ascii
    $s4  = "   -ml     Generate live dump using native support (Windows 8.1 and above only)." fullword ascii
    $s5  = "   -k      Specifies complete path and filename of debugger image to execute" fullword ascii
    $s6  = "   -b      Batch mode, don't prompt to execute kd again after completion" fullword ascii
    $s7  = "          Use -k <path to 32-bit debugger directory>\\kd.exe" fullword ascii
    $s8  = "           0200 - AWE user pages,   0400 - driver pages,  0800 - kernel stacks" fullword ascii
    $s9  = "           included in a mirror dump.  Only effective with the -m option." fullword ascii
    $s10 = "           This option may be used with -o to save faster, consistent dumps." fullword ascii
    $s11 = "   -p      Pauses the target Hyper-V VM while LiveKd is active" fullword ascii
    $s12 = "lEnsure that your symbol path is correctly configured, either via the -y option" fullword wide
    $s13 = "           0040 - system PTEs,      0080 - session pages, 0100 - metadata files" fullword ascii
    $s14 = "   -w      Runs windbg instead of kd" fullword ascii
    $s15 = "   -o      Saves a memory.dmp to disk instead of launching the debugger" fullword ascii
    $s16 = "           Mirror dumps require Windows Vista or Windows Server 2008 or above." fullword ascii
    $s17 = "   -vsym   Displays verbose debugging information about symbol load operations." fullword ascii
    $s18 = "           The default captures most kernel memory contents and is recommended." fullword ascii
    $s19 = "           0008 - page table pages, 0010 - paged pool,    0020 - non-paged pool" fullword ascii
    $s20 = "           1000 - WS metadata,      2000 - large pages" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}