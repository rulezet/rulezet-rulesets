rule Virus_Hijack_GenPack_Backdoor_Hangup_B_96 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_96.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8319ed423d864611140b823c88289eb7d509d85634f1dd7dabd89ace3db29206"

  strings:
    $s1 = "{Land hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}