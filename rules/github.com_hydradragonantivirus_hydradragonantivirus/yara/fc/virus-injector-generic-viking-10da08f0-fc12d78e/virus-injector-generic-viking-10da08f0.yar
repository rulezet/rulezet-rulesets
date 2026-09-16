rule Virus_Injector_Generic_Viking_10DA08F0 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.10DA08F0.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bb2c2bcce8b368dab7d3e9d243feb6d471d3b727db1780be31693da78bb085f"

  strings:
    $s1 = "aLky;," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}