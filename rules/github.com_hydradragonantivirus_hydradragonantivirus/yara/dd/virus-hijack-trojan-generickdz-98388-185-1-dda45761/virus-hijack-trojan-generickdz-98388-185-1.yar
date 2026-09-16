rule Virus_Hijack_Trojan_GenericKDZ_98388_185_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90570077588009d499bea40f37454fe7557734fac5c233c4d9e1b94448f44b5f"

  strings:
    $s1 = "zs4P:WYnN" fullword ascii
    $s2 = " ToFFy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}