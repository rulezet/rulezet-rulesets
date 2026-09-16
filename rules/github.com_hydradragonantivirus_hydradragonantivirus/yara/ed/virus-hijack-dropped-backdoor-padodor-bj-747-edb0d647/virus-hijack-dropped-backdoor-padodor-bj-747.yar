rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_747 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_747.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79c507d28f38058560f006ef6787cc6331d0001d29a1d8b1ec4fb1478775983e"

  strings:
    $s1 = "zare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}