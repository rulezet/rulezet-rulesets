rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_98_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_98_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb8b04cf74c09368b74257febfa44825afafe497b54e66859bfc46b158612d73"

  strings:
    $s1 = "\"What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}