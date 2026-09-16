rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_248_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_248_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb794aca29e18ad0fa76d12cff9b4f8af3cf9144de9ef6956cafbc0ffa7e777b"

  strings:
    $s1 = "}you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}