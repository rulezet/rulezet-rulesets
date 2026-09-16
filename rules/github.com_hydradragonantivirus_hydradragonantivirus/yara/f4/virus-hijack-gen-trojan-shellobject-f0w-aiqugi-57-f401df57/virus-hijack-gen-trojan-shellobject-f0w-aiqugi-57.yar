rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_57 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_57.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "076a8ead54b2a61c0915a91f54f86d9b9ac4a1406e22226123c76d7ea4e4f4b8"

  strings:
    $s1 = "Z4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}