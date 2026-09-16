rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c1f80bd32788e04ca59d842431735d12544c1bd88a7ffda579015c21238af60"

  strings:
    $s1 = "-&hiGh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}