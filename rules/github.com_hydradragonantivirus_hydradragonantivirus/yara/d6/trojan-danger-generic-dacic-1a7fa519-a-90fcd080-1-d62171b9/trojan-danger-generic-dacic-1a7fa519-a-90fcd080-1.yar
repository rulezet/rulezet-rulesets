rule Trojan_Danger_Generic_Dacic_1A7FA519_A_90FCD080_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.90FCD080_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb86eff07180008068e49769fcd8d87c2e33b01686edcb1f5355460b0330fb7b"

  strings:
    $s1 = "-!policy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}