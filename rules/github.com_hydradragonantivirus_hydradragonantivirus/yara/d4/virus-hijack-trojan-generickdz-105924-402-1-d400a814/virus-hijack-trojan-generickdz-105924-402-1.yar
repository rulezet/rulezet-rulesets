rule Virus_Hijack_Trojan_GenericKDZ_105924_402_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_402_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "582fc32224b7db1d7adf9318e4465e827c41810a04d2cb80bec08038fd465ad0"

  strings:
    $s1 = "rYAl)h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}