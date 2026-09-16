rule Virus_Sysbot_Trojan_GenericKD_45640429 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.45640429.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd4644ff6ce8d69c4ab9346ea0fc0ee39bb505d339d96af92abdf07a42f98b86"

  strings:
    $s1 = "@~~@Window Updates@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}