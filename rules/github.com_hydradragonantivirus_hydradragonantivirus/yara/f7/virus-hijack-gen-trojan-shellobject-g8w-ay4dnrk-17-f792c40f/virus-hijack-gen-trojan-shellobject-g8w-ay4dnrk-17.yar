rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5883c042e5218164dbcce64826e85feedda1c0548343a7a6df31b120b7fab1dc"

  strings:
    $s1 = "F'America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}