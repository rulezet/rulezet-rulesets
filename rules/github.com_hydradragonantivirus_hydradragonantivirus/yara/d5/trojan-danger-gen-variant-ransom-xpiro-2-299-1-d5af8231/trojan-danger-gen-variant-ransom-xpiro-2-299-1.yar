rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_299_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20fc2ff96f796e9c370f38714288337563c41b24911cf8dcd44036a721b55475"

  strings:
    $s1 = "Zsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}