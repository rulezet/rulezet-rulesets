rule Trojan_Danger_Trojan_GenericKD_67166905_91_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "446f62a7c6cccefffbccc642f586cc7400462b06454eb41ae33ef293d75d3895"

  strings:
    $s1 = "otpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}