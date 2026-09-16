rule Virus_Autorun_Win32_Neshta_A_29_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16289328666ed6ea016e57b2cd5fd7e9e721ae44e1ada15065fb2cd566cfc2be"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}