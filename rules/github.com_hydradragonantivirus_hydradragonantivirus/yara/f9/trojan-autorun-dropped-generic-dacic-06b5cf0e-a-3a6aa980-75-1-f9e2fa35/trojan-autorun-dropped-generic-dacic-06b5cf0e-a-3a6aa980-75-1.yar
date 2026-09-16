rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f903f6e03b2619f506c8ca5cf657f2aa3ba6aac74a852175f2770a907542d747"

  strings:
    $s1 = "Remote Service Application" fullword wide
    $s2 = "~n)hOTI" fullword ascii
    $s3 = "d!sNOd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}