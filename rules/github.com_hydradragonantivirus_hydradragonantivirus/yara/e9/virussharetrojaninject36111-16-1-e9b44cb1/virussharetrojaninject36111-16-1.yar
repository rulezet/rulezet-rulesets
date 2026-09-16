rule VirusShareTrojanInject36111_16_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8a258d837b711853bfc80bd4867b5245dae267a2bce40871360d7d4599e1af0"

  strings:
    $s1  = "Circle #1" fullword wide
    $s2  = "Shapes Collection" fullword wide
    $s3  = "Copyright (C) 2014-2021" fullword wide
    $s4  = "198 Protector V2" fullword ascii
    $s5  = "Delegate Using the Anonymous Method" fullword wide
    $s6  = "Delegate Using the Named Method" fullword wide
    $s7  = " studentQuery2: select range_variable.Property" fullword wide
    $s8  = " Area = " fullword wide
    $s9  = "Square #1" fullword wide
    $s10 = "Rectangle #1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}