rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_145_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_145_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43419e82c9e550f28825dd50f719e2897f500e06eac805c9ed78cf6e92517406"

  strings:
    $s1 = "l6must be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}