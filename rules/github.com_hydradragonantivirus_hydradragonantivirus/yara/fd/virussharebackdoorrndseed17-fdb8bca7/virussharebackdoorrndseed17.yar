rule VirusShareBackDoorRndseed17 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorRndseed17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fca5064b5482ad458ee4d537ea4da9a2bd5356040f7d7b9589ef291d2c1504eb"

  strings:
    $s1 = "TASs}p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}