rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bea7753e080ccb4588649c2e4e30e1399d55493c6efd6ca3b6816fe9b171c136"

  strings:
    $s1 = "!b4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}