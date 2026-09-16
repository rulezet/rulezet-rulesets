rule Virus_Hijack_Trojan_GenericKDZ_103285_725 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_725.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "499abb45291ee43c448b22e68dd8197f7122b5a3da1b3b27123df5b450696614"

  strings:
    $s1 = "%\\purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}