rule Virus_Delself_Trojan_GenericKD_38632388_2 {
  meta:
    description = "datamaliciousorder - file Virus.Delself_Trojan.GenericKD.38632388_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca716b55c9fe4a2cc0064f7965f4316c86eb688e4f7e48910460e84b4485b20"

  strings:
    $s1 = "Microsoft Office Outlook 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}