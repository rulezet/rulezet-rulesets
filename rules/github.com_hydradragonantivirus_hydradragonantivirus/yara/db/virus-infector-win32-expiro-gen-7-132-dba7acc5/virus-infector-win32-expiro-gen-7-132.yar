rule Virus_Infector_Win32_Expiro_Gen_7_132 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_132.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "756439cafcc89b98a9f7d6777ca3a5d1e034b3b1997d42472243cbce0e187be7"

  strings:
    $s1 = "ScYT*E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}