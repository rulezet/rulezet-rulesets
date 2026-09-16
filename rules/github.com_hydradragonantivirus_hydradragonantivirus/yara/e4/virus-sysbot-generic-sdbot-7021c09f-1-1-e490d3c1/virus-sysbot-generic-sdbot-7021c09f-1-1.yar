rule Virus_Sysbot_Generic_Sdbot_7021C09F_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Generic.Sdbot.7021C09F_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b6a96a8ba33b43267e1bbfce8228b6289393ba0d6d2f67991eed5ed8b523e28"

  strings:
    $s1 = "}pOLE%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}