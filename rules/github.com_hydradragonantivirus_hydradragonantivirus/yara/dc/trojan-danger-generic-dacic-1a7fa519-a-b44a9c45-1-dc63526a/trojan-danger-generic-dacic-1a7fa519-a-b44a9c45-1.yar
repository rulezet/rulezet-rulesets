rule Trojan_Danger_Generic_Dacic_1A7FA519_A_B44A9C45_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.B44A9C45_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "25506e45dfa52053299fbd2afc51ec9dea83728714a514c6b73e59c406be881d"

  strings:
    $s1 = "\\policy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "a?kAMe DZ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}