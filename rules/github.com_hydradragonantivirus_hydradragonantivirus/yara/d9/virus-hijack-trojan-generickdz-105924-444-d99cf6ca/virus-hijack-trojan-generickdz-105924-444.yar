rule Virus_Hijack_Trojan_GenericKDZ_105924_444 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_444.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89ded68afda16ebff0e90000142da8e864699de0a920ffa1426bd34d31dc519f"

  strings:
    $s1 = "rESP**" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}