rule Virus_Hijack_Trojan_Agent_DQQO_207 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_207.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afeab50b56b86c8d4a89aa4d450c5d6b507a2285e1c4c759bb28ee1da5d94c83"

  strings:
    $s1 = "LOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}