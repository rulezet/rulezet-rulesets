rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_180_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_180_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09fc2a74556fbc04227f566595a070f11656d53c0a061f78c61c4a9bcb01f0ec"

  strings:
    $s1 = "$You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}