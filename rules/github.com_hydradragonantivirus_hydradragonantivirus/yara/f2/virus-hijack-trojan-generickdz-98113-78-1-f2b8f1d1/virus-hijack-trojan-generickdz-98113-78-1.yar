rule Virus_Hijack_Trojan_GenericKDZ_98113_78_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_78_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa01c4ed33035ca6acc3deb81e3cb667ffec9ae587a330e9e312a64c49169256"

  strings:
    $s1 = ">gENIP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}