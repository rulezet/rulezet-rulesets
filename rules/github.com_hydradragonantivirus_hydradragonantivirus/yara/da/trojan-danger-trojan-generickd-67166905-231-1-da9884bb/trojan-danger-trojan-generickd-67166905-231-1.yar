rule Trojan_Danger_Trojan_GenericKD_67166905_231_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_231_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c319df93cddd62e92268f8321e1e36829422949ae34d26fd37a3dee4d8eb5da5"

  strings:
    $s1 = "k\"What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}