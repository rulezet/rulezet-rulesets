rule Virus_Hijack_Gen_Trojan_ShellObject_oyZ_ayMBdto_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.oyZ@ayMBdto_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc7f7b9a662b198e1bffc8b4bf7e770edb81ffe70d8643bde7cf82d9c860184"

  strings:
    $s1 = "SELECT Name, VideoProcessor FROM Win32_VideoController" fullword wide
    $s2 = "Shell Infrastructure Host" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}