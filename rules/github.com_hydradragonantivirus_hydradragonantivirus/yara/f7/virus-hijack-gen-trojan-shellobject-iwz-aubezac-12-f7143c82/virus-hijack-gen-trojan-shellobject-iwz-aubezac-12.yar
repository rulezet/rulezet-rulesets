rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c093ac1dc39c641da6600cfeabb1972b9111eb3e2e4b074842e0547c22757a3d"

  strings:
    $s1 = "vautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}