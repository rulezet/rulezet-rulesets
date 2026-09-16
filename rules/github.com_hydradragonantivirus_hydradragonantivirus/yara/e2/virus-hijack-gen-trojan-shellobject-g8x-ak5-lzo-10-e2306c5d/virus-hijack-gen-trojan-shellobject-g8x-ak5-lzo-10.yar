rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f79ec5328f1bbd1bfe2a84f7d83fc95c3273b2043eb82b406ca3074c13ccfbe1"

  strings:
    $s1 = "5University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}