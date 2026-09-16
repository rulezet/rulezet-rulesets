rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_aCkwazk_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@aCkwazk_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f509a1bc749e48638054622484154cf57c42d7e95fe018bed9479c68e1f4764f"

  strings:
    $s1 = "O0by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}