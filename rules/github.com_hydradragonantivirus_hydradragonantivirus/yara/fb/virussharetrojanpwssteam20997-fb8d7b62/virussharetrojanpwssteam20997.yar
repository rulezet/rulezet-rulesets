rule VirusShareTrojanPWSSteam20997 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSSteam20997.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4da051820aa16c3258fa1b3c276a42df4f5a6006ce820ae26bc0bcc3a3fef3a7"

  strings:
    $s1 = "Complete Rite Inc.1" fullword ascii
    $s2 = "sArK s[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}