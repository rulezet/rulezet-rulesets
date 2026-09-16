rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_261 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_261.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "351fd676142e987aa5b55d61cb00c656a3ec57ad60b0d30896a64ec8e0c1e31c"

  strings:
    $s1 = "\"iare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}