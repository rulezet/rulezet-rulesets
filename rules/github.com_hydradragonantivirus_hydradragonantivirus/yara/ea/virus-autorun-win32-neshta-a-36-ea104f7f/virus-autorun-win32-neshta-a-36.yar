rule Virus_Autorun_Win32_Neshta_A_36 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_36.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e98253bb53309b38ff13ca77053a2b20fce1ea3cdf83b71ff8baf4e11e8a88d"

  strings:
    $s1 = "This installer database contains the logic and data required to install Grundl" fullword ascii
    $s2 = "r HP Deskjet 5520 series." fullword ascii
    $s3 = "Windows Installer XML (3.5.2519.0)" fullword ascii
    $s4 = "r HP Deskjet 5520 series" fullword ascii
    $s5 = "Voting" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}