rule Virus_Hijack_Gen_Trojan_ShellObject_m8W_aW0I0Cd_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8W@aW0I0Cd_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce1807250ed28a3d23ec6c53ea1b71250cb406adfc9abb70f9a491dea531874"

  strings:
    $s1 = "Y$faKe{~" fullword ascii
    $s2 = "(C) 2017-2021 NVIDIA Corporation. All rights reserved." fullword wide
    $s3 = "COra$g;" fullword ascii
    $s4 = "SIKE L-" fullword ascii
    $s5 = "VIOl<x" fullword ascii
    $s6 = "_@DoWD'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}