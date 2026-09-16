rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_54 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_54.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e82e8cc1251016b2f7a99cd0ec03f94b147c26d6cd5337e7b0dfe24ac33e1725"

  strings:
    $s1 = "B4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}