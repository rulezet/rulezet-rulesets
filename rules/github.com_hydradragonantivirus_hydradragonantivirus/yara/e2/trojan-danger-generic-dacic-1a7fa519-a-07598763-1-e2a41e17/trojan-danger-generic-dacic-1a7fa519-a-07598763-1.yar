rule Trojan_Danger_Generic_Dacic_1A7FA519_A_07598763_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.07598763_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19944362a5a2bb5a4180dd27f464833b93d530faa192e0422cb9c8d4e8b7fe91"

  strings:
    $s1 = "HOrn;}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}