rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_293 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_293.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c903dc2236c11009d4daef07e410ff6307d890c2f7a11fb9663252378e3ca9bf"

  strings:
    $s1 = "}1are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}