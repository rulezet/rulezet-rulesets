rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3f65dabea1f49a9cb0f0a2bddae91aa1d11a699df5c88efc12dc92e50bab93f"

  strings:
    $s1 = "GUID passed by Logsession is written to registry" fullword ascii
    $s2 = "Copyright 2008-15 Adobe Systems Incorporated. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}