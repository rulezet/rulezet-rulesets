rule Virus_Hijack_Trojan_GenericKDZ_74550_373_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_373_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b93753b82cb16cb44b9a846d35aa6ced9c26f35b6543eb4fcba831966aa2f43c"

  strings:
    $s1 = "e$PUCK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}