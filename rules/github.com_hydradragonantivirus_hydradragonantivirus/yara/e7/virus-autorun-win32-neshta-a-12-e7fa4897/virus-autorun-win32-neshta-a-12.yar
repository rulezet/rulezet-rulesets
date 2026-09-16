rule Virus_Autorun_Win32_Neshta_A_12 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f8c795051d4ff7f742f3ad1484ee32764595ab5bd28a874da7ee246a79108a8"

  strings:
    $s1 = "support@fork.dev0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}