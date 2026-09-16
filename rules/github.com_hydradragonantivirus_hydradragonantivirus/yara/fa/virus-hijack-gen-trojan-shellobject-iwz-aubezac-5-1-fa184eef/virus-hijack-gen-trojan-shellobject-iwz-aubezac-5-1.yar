rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3b9339842edd77bdbb8249d475c76676e7e4193e430255c5ba10a37e4248633"

  strings:
    $s1 = "Execution Failed Code:" fullword ascii
    $s2 = "Error DownloadFile2 Code:" fullword ascii
    $s3 = "Error DownloadFile1 Code:" fullword ascii
    $s4 = "Read File Error" fullword ascii
    $s5 = "Error LoadFile Code:" fullword ascii
    $s6 = "Agent?" fullword ascii
    $s7 = "Internet Error" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}