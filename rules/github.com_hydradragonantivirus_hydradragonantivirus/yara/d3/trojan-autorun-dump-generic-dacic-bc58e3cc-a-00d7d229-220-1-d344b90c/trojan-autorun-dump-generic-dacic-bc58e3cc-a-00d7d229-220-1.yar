rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_220_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_220_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f78c09bebe756ebd19ae355c61d200e617e1dccd9ef6b2200a991d6918ff5f21"

  strings:
    $s1 = "jmust be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}