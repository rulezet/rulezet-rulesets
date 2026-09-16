rule VirusShareBATSiggen250_114_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBATSiggen250_114_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0f8827ba45099239e44066fd955edd89013b78a251da9aaaa35033aa5664fb4"

  strings:
    $s1 = "(Future Studio)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}