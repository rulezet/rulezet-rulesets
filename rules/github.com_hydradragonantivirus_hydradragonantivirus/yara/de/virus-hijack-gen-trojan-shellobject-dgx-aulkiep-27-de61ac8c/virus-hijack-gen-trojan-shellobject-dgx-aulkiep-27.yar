rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_27 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c9946c672b8cfbc708125766eaae4112868dddeffa54c3f7d2c9b404916a45"

  strings:
    $s1 = "U:shOW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}