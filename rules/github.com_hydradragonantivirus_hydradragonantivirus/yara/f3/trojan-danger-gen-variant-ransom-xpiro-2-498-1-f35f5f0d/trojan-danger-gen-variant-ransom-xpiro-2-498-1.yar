rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_498_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_498_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fed5045deafa8f7544a92f10d984f6ffaa0d1cab3a33912bb37dd445e613b7c5"

  strings:
    $s1 = "imust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}