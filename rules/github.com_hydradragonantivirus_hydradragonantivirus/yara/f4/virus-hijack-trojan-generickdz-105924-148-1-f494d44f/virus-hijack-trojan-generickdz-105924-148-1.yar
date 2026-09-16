rule Virus_Hijack_Trojan_GenericKDZ_105924_148_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce0abdfc1e9def4b2084cfbd0970a5aa5a7b028477b8900b01fa35458b1d0948"

  strings:
    $s1 = "/C chcp 65001 && ping 127.0.0.1 && DEL /F /S /Q /A \"" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}