rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_119_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b3ca8ffd245d8575a5a068f36aa77d67e16c9178f0b0b8f5d024a273945cabb"

  strings:
    $s1 = "*yautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}