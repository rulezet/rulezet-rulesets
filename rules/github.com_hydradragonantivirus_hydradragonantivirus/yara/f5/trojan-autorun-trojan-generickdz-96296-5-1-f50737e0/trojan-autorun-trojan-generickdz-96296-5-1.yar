rule Trojan_Autorun_Trojan_GenericKDZ_96296_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.96296_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45470c9c1b79593a522b4e95195560920f34350b70d2b8e37c9c25cb671d968b"

  strings:
    $s1 = "Lthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}