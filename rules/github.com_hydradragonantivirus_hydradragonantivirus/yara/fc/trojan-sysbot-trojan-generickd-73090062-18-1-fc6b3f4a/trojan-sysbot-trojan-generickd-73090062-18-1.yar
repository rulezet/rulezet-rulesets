rule Trojan_Sysbot_Trojan_GenericKD_73090062_18_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.73090062_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81ceed8e188167092d3159de5e926c11bff3142969228ef040667cef61edc5bd"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}