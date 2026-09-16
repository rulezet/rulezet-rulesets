rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_563_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_563_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8af918b836c4c9b4a005524e2b31a6254380230f0cbc4ba82f32eb312b1dd536"

  strings:
    $s1 = "tuw{coSt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}