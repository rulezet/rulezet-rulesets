rule Virus_Hijack_Trojan_GenericKDZ_98388_60_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_60_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a92a2f6c7bc7ce5b4e08a9e4b50608f7bc7285eba1f7114470ae33742144ef66"

  strings:
    $s1 = "e[^$LAIr" fullword ascii
    $s2 = ")WaNdy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}