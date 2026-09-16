rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_131_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_131_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fefd62835c38188719fa44a8da9971cb37dd131d1219d0b834c4b891117a0eda"

  strings:
    $s1 = "VUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}