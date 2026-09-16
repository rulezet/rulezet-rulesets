rule VirusShareTrojanSiggen1961528_15_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1533414d7249d5e78c335c618644d74af00f7ee0209effd400f50f3249c2ff03"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}