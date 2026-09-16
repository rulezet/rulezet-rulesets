rule Virus_Hijack_Trojan_GenericKDZ_74550_55_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d635daee4f8a8fca5ac4f26305bda2d7c9ddf512ec3d864d95559976a1d698fd"

  strings:
    $s1 = "gRAd%[&" fullword ascii
    $s2 = "[CIrca" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}