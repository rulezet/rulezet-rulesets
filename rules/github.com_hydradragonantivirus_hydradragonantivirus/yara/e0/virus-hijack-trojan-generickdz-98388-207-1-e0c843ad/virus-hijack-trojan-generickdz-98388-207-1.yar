rule Virus_Hijack_Trojan_GenericKDZ_98388_207_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2a01fca72b62a9f296284edf5ff140c94912763cb00b15256fc8b3b5c327a9b"

  strings:
    $s1 = "ROdD)F" fullword ascii
    $s2 = "j:moko" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}