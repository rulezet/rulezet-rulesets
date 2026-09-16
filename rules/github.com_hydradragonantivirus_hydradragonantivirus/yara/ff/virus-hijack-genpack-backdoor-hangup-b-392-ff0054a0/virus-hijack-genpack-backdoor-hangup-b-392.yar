rule Virus_Hijack_GenPack_Backdoor_Hangup_B_392 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_392.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d649d70ff1180ff86c603916e99fcda22a98b4f28f034a41aeb3f7bec671a18d"

  strings:
    $s1 = "-,A. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}