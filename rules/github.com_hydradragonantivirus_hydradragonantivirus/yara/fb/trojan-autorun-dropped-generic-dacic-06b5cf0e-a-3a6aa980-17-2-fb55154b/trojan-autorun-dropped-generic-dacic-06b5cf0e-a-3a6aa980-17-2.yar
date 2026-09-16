rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_17_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "246df48db7bcf11b34ee1f63025f8dffb1c29daf35f5e9eb68555b3e3447b4d1"

  strings:
    $s1 = "Giz kodota tiziwibumap<Pegis lul jefimiwifeyopud remosacuhuyige cimeganoregiwu cuya" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}