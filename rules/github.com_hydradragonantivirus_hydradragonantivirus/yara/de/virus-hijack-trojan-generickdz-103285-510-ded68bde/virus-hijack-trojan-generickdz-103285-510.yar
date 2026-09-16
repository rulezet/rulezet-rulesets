rule Virus_Hijack_Trojan_GenericKDZ_103285_510 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_510.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24176e14013cacf25db8b20554e314b01c29a7d21e26f2ddae621aea6e5e96e6"

  strings:
    $s1 = "|cavailable at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}