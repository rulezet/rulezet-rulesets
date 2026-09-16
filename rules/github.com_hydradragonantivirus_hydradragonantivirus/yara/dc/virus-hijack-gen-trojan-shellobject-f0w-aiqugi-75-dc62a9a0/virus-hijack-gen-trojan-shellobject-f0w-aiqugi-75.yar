rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_75 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_75.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3447df15be7ffc3c9e76dafffd457b6decfc3ab1b51189981580d36f4b97ac4"

  strings:
    $s1 = "_T4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}