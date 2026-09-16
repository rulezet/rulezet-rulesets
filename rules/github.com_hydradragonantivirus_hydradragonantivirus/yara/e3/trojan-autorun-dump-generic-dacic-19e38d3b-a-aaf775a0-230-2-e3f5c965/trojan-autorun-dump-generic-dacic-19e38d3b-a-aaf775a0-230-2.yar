rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_230_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_230_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5463ffb9b3e72ec2b7926ddf4e1bf9a940ed0b4ecbc4a66d8f4c9d6caae6f0d"

  strings:
    $s1 = "thEB'Q" fullword ascii
    $s2 = ";%UnbE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}