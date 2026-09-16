rule Trojan_Danger_Trojan_GenericKD_67269844_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0670010ceb5621f2625fe86bf8b0aaa3f15e996e0d33f523cab81b69696597d"

  strings:
    $s1 = "*policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}