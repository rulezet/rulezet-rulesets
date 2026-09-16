rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_50 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6d9a50cc638d314f27db17556879f8659ccf3816f60f16298c72cc1da88716"

  strings:
    $s1 = "K[4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}