rule Trojan_Danger_Generic_Dacic_1A7FA519_A_881114F5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.881114F5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb1e3d0517d8461a5be621fa2bc6f9f690574662399ada0ddf698f7f7b9150c5"

  strings:
    $s1 = "\\What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}