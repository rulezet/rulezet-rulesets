rule Virus_Hijack_Gen_Trojan_ShellObject_LzZ_aWELKOd_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.LzZ@aWELKOd_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b755d5dd56b59a6f5437e8d63c04ef3f30f0bea0704ee7578a2f5d1c0f33ef60"

  strings:
    $s1 = "TIFf,L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}