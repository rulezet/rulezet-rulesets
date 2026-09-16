rule Trojan_Homepage_Trojan_GenericKD_63563925_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Homepage_Trojan.GenericKD.63563925_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6542c9faedb807cb5fdaf18acc12838adcbc64c129528e00894f0e0ca192735"

  strings:
    $s1 = "Mozilla/5.0 (compatible; Konqueror/4.3; Linux) KHTML/4.3.5 (like Gecko)" fullword ascii
    $s2 = "Mozilla/4.0 (compatible; MSIE 6.0; America Online Browser 1.1; rev1.5; Windows NT 5.1;)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}