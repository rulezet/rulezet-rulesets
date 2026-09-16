rule Virus_Hijack_Trojan_GenericKDZ_105924_227_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49d57e422319b9ebb5a4f41fcb62c236ef4492bad6bb62ad758524f84e3938e3"

  strings:
    $x1 = "C:\\\\Program Files\\Adobe\\Acrobat Reader DC\\Reader\\Browser\\WCChromeExtn\\WCChromeNativeMessagingHost.exe" fullword ascii
    $s2 = "Copyright 1984-2017 Adobe Systems Incorporated" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}