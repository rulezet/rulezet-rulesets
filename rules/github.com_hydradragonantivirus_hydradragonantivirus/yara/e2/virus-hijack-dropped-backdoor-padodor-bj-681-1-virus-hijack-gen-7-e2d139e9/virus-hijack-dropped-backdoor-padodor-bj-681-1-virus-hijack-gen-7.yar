import "pe"
rule _Virus_Hijack_Dropped_Backdoor_Padodor_BJ_681_1_Virus_Hijack_Gen_7 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Dropped.Backdoor.Padodor.BJ_681_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.@JZ@ayM4QWg_8_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_1_1.vir, Virus.Hijack_Gen.Variant.Zusy.540394.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11fb2b7a48f07beeec6a86851406c6783a39b758dc13b6387389007245c80005"
    hash2       = "799e5d1ba0f5eb26b4b5aa29c9f13e89ac5fed2702b132052c77a1ac460bc74f"
    hash3       = "473f11f811a9eca38ac7b8df2dd096d2437a8cb6736118bda32c378873380972"
    hash4       = "5c4fc9a5b0a43de151b3c151fc1153c2054f3d4bd34e2a466549aac6f9ccc87f"
    hash5       = "23f7e5902489b00fa4647c707ce5d9beaca43465af60b313261f54059d894e7a"

  strings:
    $s1 = "$Sped?Z" fullword ascii
    $s2 = "MASH{\\" fullword ascii
    $s3 = "aSOK Q6" fullword ascii
    $s4 = "rO`Dray" fullword ascii
    $s5 = "?YM}puDu" fullword ascii
    $s6 = "%#aBLE" fullword ascii
    $s7 = "L!fiaT" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8a7144716015fefc4920a45528d0fa9a" and (all of them)
    ) or (all of them)
}