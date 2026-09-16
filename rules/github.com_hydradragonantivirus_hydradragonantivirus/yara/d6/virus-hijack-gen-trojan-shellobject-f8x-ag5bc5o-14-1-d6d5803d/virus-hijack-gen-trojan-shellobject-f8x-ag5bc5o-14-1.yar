rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b7f48b28dbf1708001a953d36420d9e8e92ab323be2766db3b1afdaa2424c0"

  strings:
    $s1 = "Fneed dictionary" fullword ascii
    $s2 = "About Naver" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}