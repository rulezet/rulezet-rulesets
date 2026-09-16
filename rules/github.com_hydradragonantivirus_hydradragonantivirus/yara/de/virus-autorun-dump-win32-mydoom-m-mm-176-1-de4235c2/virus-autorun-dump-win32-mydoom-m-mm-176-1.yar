rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_176_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_176_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a84340037d91a697cb4a96739fa3b160efe73e495f21fbc6f49775bb6520b9"

  strings:
    $s1 = "Microsoft Office OneNote 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}