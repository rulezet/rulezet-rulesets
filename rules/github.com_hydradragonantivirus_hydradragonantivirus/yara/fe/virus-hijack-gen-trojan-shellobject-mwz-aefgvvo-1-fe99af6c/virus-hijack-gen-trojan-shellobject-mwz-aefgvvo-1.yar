rule Virus_Hijack_Gen_Trojan_ShellObject_mWZ_aeFgVVo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb4add64ce16513a9a71861a499b0cabd28b4f3a55e0b601765b76c04f76a74f"

  strings:
    $s1 = "`shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}