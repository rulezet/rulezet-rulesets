rule Virus_Hijack_Trojan_GenericKDZ_105924_375_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_375_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b4417929f4866237b639122afbe454c8a041ed9ee9f1bddeeffe4d56233988"

  strings:
    $s1 = "=`pRUt" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}