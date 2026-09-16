rule Virus_Hijack_Gen_Trojan_ShellObject_j4Z_aqH1LVc_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j4Z@aqH1LVc_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1581c975ec062365d4434b399ce3b139c60d8e0ff70685ac66fba98648aba8a9"

  strings:
    $s1 = "eneral Public License along with " fullword wide
    $s2 = "This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as pub" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}