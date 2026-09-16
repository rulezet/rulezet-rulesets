rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f712e9dd23c20a3b52e575a036d0217b0262d40ff9766bd0086c63cdd6693e71"

  strings:
    $s1 = "<description>App1029</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}