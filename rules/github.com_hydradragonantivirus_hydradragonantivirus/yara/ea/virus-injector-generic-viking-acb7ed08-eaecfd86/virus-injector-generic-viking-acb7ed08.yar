rule Virus_Injector_Generic_Viking_ACB7ED08 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.ACB7ED08.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23abff5c992a30bf11d14ec0267d7d9331809fbc5b8a845d173b8160ce5b0b30"

  strings:
    $x1 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker" ascii
    $s2 = "yALPC Port" fullword wide
    $s3 = "Copyright 2022 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}