rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef7bf0655d8f55ef3a015669876478c26be30073c81e3cf6a13e368706e6606a"

  strings:
    $s1 = "!This HlZWl97 cannot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}