rule Virus_Hijack_Gen_Trojan_ShellObject_uCZ_amHJK4p_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uCZ@amHJK4p_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9e9921f17350a6b2f1af37ac6649803b01f97d06cbd66535cffb726b053bbbd"

  strings:
    $s1 = "Windows Task Manager" fullword ascii
    $s2 = "Microsoft Windows Spooler" fullword wide
    $s3 = "time e" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}