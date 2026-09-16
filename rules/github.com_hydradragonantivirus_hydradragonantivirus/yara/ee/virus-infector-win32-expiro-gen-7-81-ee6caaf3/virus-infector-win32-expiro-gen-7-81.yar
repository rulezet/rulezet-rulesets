rule Virus_Infector_Win32_Expiro_Gen_7_81 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_81.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bf04c291507af6ab783b0bf16436add73457e4c2607c619e04c1993b4cf18d1"

  strings:
    $s1 = "bENA!\"" fullword ascii
    $s2 = "MULE]gF" fullword ascii
    $s3 = "swAG$J" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}