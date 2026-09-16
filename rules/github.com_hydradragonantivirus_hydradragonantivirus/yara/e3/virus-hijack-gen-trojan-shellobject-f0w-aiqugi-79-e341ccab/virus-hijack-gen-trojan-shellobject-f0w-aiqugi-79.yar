rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_79 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_79.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e1524147a2ffe4946506a4f07f41591d86f01c3754dd3d49d6133b874f60191"

  strings:
    $s1 = "F4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}