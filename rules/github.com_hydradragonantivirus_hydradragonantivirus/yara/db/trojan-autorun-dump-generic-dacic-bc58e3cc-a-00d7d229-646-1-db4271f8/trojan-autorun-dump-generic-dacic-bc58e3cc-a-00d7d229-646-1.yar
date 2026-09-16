rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_646_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_646_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07f0122d51fb0e7c973693650a75f2f777321c0dcaac7c54a9013a3851fc6e7e"

  strings:
    $s1 = ">of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}