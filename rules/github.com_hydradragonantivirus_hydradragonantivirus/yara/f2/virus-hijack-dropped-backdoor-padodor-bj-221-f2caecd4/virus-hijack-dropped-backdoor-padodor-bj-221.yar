rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_221 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_221.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e18eab71c9097543d3b46315468f1ef947590ac59a4c676821dd9fc520021c9"

  strings:
    $s1 = "xare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}