rule Trojan_Danger_Trojan_GenericKD_67166905_338_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_338_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83fa07e5106be70d4a9756107c163467a83fd437d534eb6b6b01a0d195b79732"

  strings:
    $s1 = "1University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}