rule Virus_Sysbot_Trojan_GenericKD_71671752_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKD.71671752_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea7d9e9b846e07ee0e1fbfde3d125cc51ee11b4a361cdae630738f59f8acd2c6"

  strings:
    $s1 = "<Module>{342B6D2C-26D1-4442-99A1-C57553C604A4}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}