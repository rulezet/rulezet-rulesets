rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66e10be266795a92ef7aa5dc014360ab1b06c991438b1d55fdf3c0f10621ef62"

  strings:
    $s1 = ",4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}