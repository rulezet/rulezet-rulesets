rule Virus_Hijack_GenPack_Backdoor_Hangup_B_102 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_102.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd63a328a00c2800541d71ead4de24f9b2dede4046a378311468da00577fc8a9"

  strings:
    $s1 = "%0your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}