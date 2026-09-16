rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a8oG5if_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oG5if_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02b759eca78e88a359b5abace93790a46cf77173832444694f03ba5d9d47947b"

  strings:
    $s1 = "{by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}