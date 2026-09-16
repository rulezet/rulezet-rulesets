rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53fe226f76fb869148496aa8dd791bc643ea4295e3eccd2e4dca617fc080ffbb"

  strings:
    $s1 = "?LAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}