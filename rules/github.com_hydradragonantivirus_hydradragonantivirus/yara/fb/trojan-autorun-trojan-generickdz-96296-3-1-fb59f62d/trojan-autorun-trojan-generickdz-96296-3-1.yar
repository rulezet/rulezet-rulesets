rule Trojan_Autorun_Trojan_GenericKDZ_96296_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.96296_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92c5ddf3c0c41a10daa855f4265cfb9ff2b5a51263044fe879230a6f57d03135"

  strings:
    $s1 = "--whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}