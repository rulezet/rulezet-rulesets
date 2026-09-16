rule Virus_Autorun_Worm_FakeDoc {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "370539139d4d055c973b5342a473a88ba05546a7fad5b6ea7e562227da60cc9d"

  strings:
    $s1 = "utAi?4" fullword ascii
    $s2 = "Sans MS" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}