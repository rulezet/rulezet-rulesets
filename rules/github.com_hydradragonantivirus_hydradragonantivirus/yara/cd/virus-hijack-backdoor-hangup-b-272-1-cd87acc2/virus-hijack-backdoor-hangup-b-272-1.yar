rule Virus_Hijack_Backdoor_Hangup_B_272_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_272_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f66def1cfd97ef30561c31188101609a0d357e60335eb197c03fcc922bad7a0b"

  strings:
    $s1 = "Target directory is %s." fullword ascii
    $s2 = "Input directory is too large." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}