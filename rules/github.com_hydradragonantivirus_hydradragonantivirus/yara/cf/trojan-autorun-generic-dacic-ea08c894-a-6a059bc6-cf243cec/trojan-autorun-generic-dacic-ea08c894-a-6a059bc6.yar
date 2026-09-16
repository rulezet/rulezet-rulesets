rule Trojan_Autorun_Generic_Dacic_EA08C894_A_6A059BC6 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.EA08C894.A.6A059BC6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b975edf11c0380c92512ee9351f97cbec956c490494a8145166a81bbcdde5195"

  strings:
    $s1 = "Pobs'I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}