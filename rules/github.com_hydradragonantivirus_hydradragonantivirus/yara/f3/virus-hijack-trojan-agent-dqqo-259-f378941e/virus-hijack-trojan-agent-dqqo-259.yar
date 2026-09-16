rule Virus_Hijack_Trojan_Agent_DQQO_259 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_259.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c3afa3e338e758e92b2037c62c7e55d374e3218b718ade1e19ad806e366dc76"

  strings:
    $s1 = "]whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}