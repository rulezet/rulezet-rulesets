import "pe"
rule _Trojan_Hooker_Gen_Variant_Barys_4848_Trojan_Hooker_Gen_Variant__58 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Gen.Variant.Barys.4848.vir, Trojan.Hooker_Gen.Variant.Barys.4848_1.vir, Trojan.Hooker_Gen.Variant.Barys.4848_2.vir, Trojan.Hooker_Gen.Variant.Barys.4848_3.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_686_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_687_1.vir, Virus.Hijack_Dropped.Backdoor.Padodor.BJ_688_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "008af2c2dd9eef114337d1ee81f1ab8bf650ee1d28cac4fbef9821cbb4effeb9"
    hash2       = "f44e107d5721b83a07cd6a95e8e7e0b2f16a46214309d6290c0ecc22f701f31b"
    hash3       = "48a0b58ae46fcd696a525c08b7e483670336f5fb4289697e231074cb8418e00b"
    hash4       = "bdafcb2d174e285f69c186424485009e0c62a342882727fde903cf3b04b11c4c"
    hash5       = "12732bd13f69e2f69148970dbaf053b6e6e5f2b49756def3769d045ae50e611f"
    hash6       = "ed715a995a82ff41bdf7c042a49eadc891958d532622b6ec6224dd6c236e8dbf"
    hash7       = "74190a9a8eed98a7d0fd9a24d13f38d42834ceb5832b132b3cc016e779006dc2"

  strings:
    $s1  = "contestably" fullword ascii
    $s2  = "boilable" fullword ascii
    $s3  = "Isogamy" fullword ascii
    $s4  = "Astonishment" fullword ascii
    $s5  = "Acquittal" fullword ascii
    $s6  = "Anthropocentric" fullword ascii
    $s7  = "Essayist" fullword ascii
    $s8  = "Criticize" fullword ascii
    $s9  = "Loftless" fullword ascii
    $s10 = "Basally" fullword ascii
    $s11 = "Dishful" fullword ascii
    $s12 = "Internuclear" fullword wide
    $s13 = "dewily" fullword ascii
    $s14 = "calculational" fullword ascii
    $s15 = "Patta figlia potuti" fullword wide
    $s16 = "Achromatically" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "94499ec57ca7f8a108e513ffe23240eb" and (8 of them)
    ) or (all of them)
}