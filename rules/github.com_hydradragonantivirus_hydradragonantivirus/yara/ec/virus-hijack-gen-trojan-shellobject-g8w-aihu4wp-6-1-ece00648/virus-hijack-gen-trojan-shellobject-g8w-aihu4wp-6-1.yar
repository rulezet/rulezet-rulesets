rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d44cf1ac0149ad1af8d125373ffad52ea3af93e8edc0e7caaa3f9efaec169ad"

  strings:
    $s1 = "cmd /c ping -n 1 localhost & del \"%s\"" fullword ascii
    $s2 = "Mozilla/5.0 (compatible)" fullword ascii
    $s3 = "Http/1.1 403 Forbidden" fullword ascii
    $s4 = "VirtualX Corporation" fullword wide
    $s5 = "<H1>403 Forbidden</H1>" fullword ascii
    $s6 = "Graphics Acceleration Program" fullword wide
    $s7 = "GPU Helper" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}