rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f9df90a049eecaa3423dbecc98869c0e535b914ff20d4d281d87ed751700b3"

  strings:
    $s1 = "pAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}