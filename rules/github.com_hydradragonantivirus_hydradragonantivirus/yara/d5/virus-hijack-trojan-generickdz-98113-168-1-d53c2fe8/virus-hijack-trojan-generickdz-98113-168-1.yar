rule Virus_Hijack_Trojan_GenericKDZ_98113_168_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_168_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ec73e3dc6659e8bcf1027b09eecdc0a2f8741532ca4f321bd4dca3a70838ecb"

  strings:
    $s1 = "`MOKi}w" fullword ascii
    $s2 = "~)b#[PASI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}