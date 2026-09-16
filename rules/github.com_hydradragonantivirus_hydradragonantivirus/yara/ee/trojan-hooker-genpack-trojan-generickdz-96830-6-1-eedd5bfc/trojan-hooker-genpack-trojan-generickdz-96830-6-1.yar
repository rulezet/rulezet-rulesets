rule Trojan_Hooker_GenPack_Trojan_GenericKDZ_96830_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_GenPack.Trojan.GenericKDZ.96830_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f596f0804fe18001cf9bbf503cd4ad2bca07e98fd0d38a55c8c195d6fd95d3a4"

  strings:
    $x1 = "Microsoft.Windows.SystemCompatible,processorArchitecture=\"x86\",publicKeyToken=\"6595b64144ccf1df\",type=\"win32\",version=\"6." wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}