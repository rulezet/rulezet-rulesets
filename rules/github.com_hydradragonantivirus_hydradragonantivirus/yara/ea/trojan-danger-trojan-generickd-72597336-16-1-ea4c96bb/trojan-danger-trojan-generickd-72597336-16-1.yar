rule Trojan_Danger_Trojan_GenericKD_72597336_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aab440dd34fecf830373b6d1072d33d338ec58cef594e90a595081b7d883394"

  strings:
    $s1 = "+University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}