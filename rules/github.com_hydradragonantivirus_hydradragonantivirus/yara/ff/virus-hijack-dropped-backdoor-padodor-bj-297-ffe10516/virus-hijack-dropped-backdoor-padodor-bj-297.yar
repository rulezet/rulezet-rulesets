rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_297 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_297.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbd91ddb3696c8fec4b0d71516f1b7866f07d49bd7f33a158730f4c37ecdec4f"

  strings:
    $s1 = "]biLo'f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}