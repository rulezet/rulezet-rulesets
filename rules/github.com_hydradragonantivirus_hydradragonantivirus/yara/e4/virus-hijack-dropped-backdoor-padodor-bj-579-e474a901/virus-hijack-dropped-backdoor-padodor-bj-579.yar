rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_579 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_579.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ec1d52716961332ee256248f23d116b1c82a203edf89c18c65ee0aaf33dd22"

  strings:
    $s1 = "A4Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}