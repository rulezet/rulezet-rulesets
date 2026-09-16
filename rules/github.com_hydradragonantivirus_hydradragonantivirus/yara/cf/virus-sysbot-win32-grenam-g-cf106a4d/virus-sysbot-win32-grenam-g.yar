rule Virus_Sysbot_Win32_Grenam_G {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Win32.Grenam.G.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "099c1f3efa740cdd236c05d17266c65655c1a7bcfcfa3850dd8628382e081f4f"

  strings:
    $s1 = "Orientation,%B" fullword ascii
    $s2 = "Color@'B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}