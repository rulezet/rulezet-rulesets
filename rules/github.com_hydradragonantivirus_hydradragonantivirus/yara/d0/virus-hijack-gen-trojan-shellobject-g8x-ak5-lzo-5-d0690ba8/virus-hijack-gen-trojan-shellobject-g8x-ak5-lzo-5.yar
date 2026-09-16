rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed8a3b0c07c427921808c4d1ac07cbcca06a0c4ba16f2c1ac346c19124cb2b03"

  strings:
    $s1 = "j'University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}