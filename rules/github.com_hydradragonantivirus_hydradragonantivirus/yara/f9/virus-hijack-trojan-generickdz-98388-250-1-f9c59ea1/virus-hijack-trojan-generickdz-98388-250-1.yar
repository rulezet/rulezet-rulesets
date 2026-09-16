rule Virus_Hijack_Trojan_GenericKDZ_98388_250_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_250_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7025c129cdf9fec422ade3369d5e875aebc30e4afc011336cc873b0ff487bf99"

  strings:
    $s1 = "name:i" fullword ascii
    $s2 = "w:REnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}