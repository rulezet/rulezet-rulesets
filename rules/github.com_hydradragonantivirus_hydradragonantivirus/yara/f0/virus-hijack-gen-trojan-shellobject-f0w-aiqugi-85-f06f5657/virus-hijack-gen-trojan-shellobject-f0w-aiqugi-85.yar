rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_85 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7340af2ca5e2b44985a8f8a90c026d7c190f8ee7690b8142705a54b6feb0e277"

  strings:
    $s1 = "1}4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}