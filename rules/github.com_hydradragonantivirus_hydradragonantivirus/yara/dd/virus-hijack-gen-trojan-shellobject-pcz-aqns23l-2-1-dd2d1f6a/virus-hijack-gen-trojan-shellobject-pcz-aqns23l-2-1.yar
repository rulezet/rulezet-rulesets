rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "857de2e2aa8a2c5787ae4aeb14cf65df91ebf57cf1731be293fe6c4f6cfe411f"

  strings:
    $s1 = "*$stow#x%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}