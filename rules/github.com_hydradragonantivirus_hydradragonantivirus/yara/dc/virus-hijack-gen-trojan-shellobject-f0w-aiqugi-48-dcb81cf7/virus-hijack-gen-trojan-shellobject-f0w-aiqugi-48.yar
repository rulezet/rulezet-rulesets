rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_48 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8a3592108dd5cc147bbe79753814f3e43e47974e03f9cda49833333ac3b5265"

  strings:
    $s1 = "V4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}