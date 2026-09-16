rule Virus_Hijack_Gen_Trojan_ShellObject_KuZ_aKo42Jj_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.KuZ@aKo42Jj_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d080e25ad67113dfa62e62db93522d76e4f68330ade24642078117281c92ecd"

  strings:
    $s1 = "soft Visual StudQn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}