rule Virus_Hijack_Gen_Trojan_ShellObject_3yZ_aWcfH4h_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.3yZ@aWcfH4h_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3bfd868352d7a187684c3e907a92120f58c18853e3a4530a5e96b471d31ca21"

  strings:
    $s1 = "convert to a perpetual license. If you extend your subscription, you may continue using th" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}