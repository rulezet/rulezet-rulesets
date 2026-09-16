rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6704d840f8858a0e7548aefb263b7b3763cdb0900c86763da039916cce7b6dd3"

  strings:
    $s1 = "|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}