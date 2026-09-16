rule Virus_Hijack_Gen_Trojan_ShellObject_r8W_au4YcDk_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.r8W@au4YcDk_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c08224f5a5e392d8c6091a0f25ae2e9219a8bda46c6b27f1658d8ccd630a4348"

  strings:
    $s1 = "lYnx)?t`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}