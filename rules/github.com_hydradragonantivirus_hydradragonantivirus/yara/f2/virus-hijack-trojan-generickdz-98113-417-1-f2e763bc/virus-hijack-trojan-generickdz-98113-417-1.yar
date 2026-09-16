rule Virus_Hijack_Trojan_GenericKDZ_98113_417_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_417_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "929e17c110957ac7a5a16a18853d5565552eff153adc7f8cb4824872a9cd87fb"

  strings:
    $s1 = "dafF&%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}