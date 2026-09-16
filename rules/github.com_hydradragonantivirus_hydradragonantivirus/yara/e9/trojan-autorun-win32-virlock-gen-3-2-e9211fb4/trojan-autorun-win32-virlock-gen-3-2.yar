rule Trojan_Autorun_Win32_Virlock_Gen_3_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e2627c9706ea3d45c4ea586b9ee94300ebc70dd1b44a6eb89359daacd89726"

  strings:
    $s1 = "+orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}