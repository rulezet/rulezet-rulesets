rule VirusShareTrojanBtcMine155 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanBtcMine155.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "073d4c2c64e9c9c4b0f423da9b333082df0c12421dd196bf8b56cf0c42b70d4e"

  strings:
    $s1 = "C:\\Users\\Alex\\Documents\\Visual Studio 2010\\Projects\\WindowsFormsApplication1\\startminer\\obj\\x86\\Debug\\WindowsTime.pdb" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}