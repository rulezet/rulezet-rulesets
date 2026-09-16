rule Virus_Hijack_GenPack_Backdoor_Hangup_B_144 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_144.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd0dd5780ddb323f5ad2911c3548cc459eaf2f87aac7d97d02268ed99b43794"

  strings:
    $s1 = "=to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}