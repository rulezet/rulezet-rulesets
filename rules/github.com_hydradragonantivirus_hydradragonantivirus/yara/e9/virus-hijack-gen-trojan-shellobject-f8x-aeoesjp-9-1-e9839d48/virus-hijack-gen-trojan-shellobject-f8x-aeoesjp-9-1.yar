rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aeOesjp_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aeOesjp_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c82204cf8c4c9d70624a8736d90bd98d9fd02106a2b4793beda22423e77b2b89"

  strings:
    $s1 = "Fneed dictionary" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}