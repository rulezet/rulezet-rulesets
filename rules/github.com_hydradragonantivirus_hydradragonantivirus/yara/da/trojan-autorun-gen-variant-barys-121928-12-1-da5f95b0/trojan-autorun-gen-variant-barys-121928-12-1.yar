rule Trojan_Autorun_Gen_Variant_Barys_121928_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Barys.121928_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cbc705ff52de18a560fb3863976872425a83a9279506c856e36832df1732a97"

  strings:
    $s1 = "nl4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}