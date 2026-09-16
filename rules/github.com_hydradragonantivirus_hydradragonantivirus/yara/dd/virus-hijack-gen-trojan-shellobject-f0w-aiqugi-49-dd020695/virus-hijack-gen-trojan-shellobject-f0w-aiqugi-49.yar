rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_49 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ae493bed7f1e0b035e82c8711bc268b1d255afef92ebb7c21c89250adacc26e"

  strings:
    $s1 = "2%4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}