rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34c6c9a1a953fd509bbc1046f256cb1735e856315e447012a5a5c5196b310259"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii
    $s2 = "Ua neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii
    $s3 = "B%liSs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}