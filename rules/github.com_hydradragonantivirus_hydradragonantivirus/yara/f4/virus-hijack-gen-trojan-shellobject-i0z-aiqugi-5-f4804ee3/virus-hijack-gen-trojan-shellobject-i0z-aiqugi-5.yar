rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2023139333bd17498381f74c6f0a8305b3b7eecf8172315a3b144384a34827af"

  strings:
    $s1 = "c4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}