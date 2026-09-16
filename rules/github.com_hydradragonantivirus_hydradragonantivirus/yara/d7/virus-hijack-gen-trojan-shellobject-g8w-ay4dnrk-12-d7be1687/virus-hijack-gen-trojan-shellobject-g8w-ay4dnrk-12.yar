rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b95ae04ec9e35bae26b10baed2f4f68e61bebb48a6d713ff77273c0591cb951"

  strings:
    $s1 = "cAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}