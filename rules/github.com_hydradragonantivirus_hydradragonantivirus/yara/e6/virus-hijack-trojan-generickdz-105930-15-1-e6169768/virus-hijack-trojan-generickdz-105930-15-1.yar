rule Virus_Hijack_Trojan_GenericKDZ_105930_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1de18360f5536c40222a49ed9348a50547ac869325511508a6f2fbcdd0213124"

  strings:
    $s1 = "Zeta nO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}