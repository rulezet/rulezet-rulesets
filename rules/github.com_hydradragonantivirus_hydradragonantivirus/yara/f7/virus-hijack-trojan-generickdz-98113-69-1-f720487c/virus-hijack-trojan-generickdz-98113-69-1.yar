rule Virus_Hijack_Trojan_GenericKDZ_98113_69_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128cd211e0792ef7d7597efabca7e81ec37c11474f4d62c0725fd19f4f9ceedd"

  strings:
    $s1 = "L`tORe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}