rule Trojan_Danger_Generic_Dacic_1A7FA519_A_CE98034F_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.CE98034F_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eaaeaef1538c565681abe77562db617d34153394e783c727effc2e0453f9d36"

  strings:
    $s1 = "VBUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}