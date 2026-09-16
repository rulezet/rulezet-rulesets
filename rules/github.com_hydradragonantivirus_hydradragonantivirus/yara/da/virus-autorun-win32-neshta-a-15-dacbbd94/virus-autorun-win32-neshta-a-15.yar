rule Virus_Autorun_Win32_Neshta_A_15 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "366d2abae63c5b2d601dc9548241494fc34c4678fe8941d910d2571e3b6c053f"

  strings:
    $s1 = "AtI;@tuwI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}