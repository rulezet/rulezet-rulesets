rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_83_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_83_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e25bc1819573769183a0a16c5f5c92e66ce927dcd87386f378a0db530f6fe0b"

  strings:
    $s1 = " Complete O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}