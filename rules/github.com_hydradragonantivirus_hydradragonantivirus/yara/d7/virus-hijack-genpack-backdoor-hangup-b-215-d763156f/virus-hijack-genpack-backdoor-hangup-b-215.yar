rule Virus_Hijack_GenPack_Backdoor_Hangup_B_215 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_215.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35cc40b62390abdbc1448f096d43fc2c4a5b62ab670c469e16fc3586eb6aefe5"

  strings:
    $s1 = "OA. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}