rule Trojan_Autorun_Gen_Variant_Ransom_Phobos_169_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1abb914686af11f38ba53e644479e46e04c3d1ec759f20b4a090f65fbe5c99c2"

  strings:
    $s1 = "zSassets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}