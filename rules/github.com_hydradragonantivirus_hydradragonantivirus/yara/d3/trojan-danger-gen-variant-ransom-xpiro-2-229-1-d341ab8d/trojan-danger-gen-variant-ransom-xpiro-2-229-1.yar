rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_229_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_229_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "458432fa175caca8d31b4a5e835fe56169dcea7764e89f241bb7aa9662610c2f"

  strings:
    $s1 = "!America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}