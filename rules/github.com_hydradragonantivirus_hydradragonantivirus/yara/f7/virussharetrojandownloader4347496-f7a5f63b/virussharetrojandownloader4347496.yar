rule VirusShareTrojanDownLoader4347496 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4347496.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49ff7ce1a1250c3b68329fae9162b9350a0df145b8b23deed2e746b932437bd1"

  strings:
    $s1 = "#Error: " fullword wide
    $s2 = "!Powered by SmartAssembly 6.6.4.95" fullword ascii
    $s3 = "Code lengths don't add up properly." fullword wide
    $s4 = "Created with" fullword wide
    $s5 = " 1998-2016 Mark Russinovich " fullword wide
    $s6 = "Copyright (C) 1998-2016 Mark Russinovich " fullword wide
    $s7 = "application data cannot be found" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}