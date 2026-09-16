rule Virus_Hijack_Gen_Trojan_ShellObject_xCZ_aC5hfel {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.xCZ@aC5hfel.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "798af42b748d98a7218a91d0156c00b1d00629f7244e9789e01b6e0104dfdc27"

  strings:
    $s1 = "r)tosY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}