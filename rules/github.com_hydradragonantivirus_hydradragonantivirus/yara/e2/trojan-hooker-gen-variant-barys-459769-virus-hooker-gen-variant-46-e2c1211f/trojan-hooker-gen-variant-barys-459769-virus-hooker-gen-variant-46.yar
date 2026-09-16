import "pe"
rule _Trojan_Hooker_Gen_Variant_Barys_459769_Virus_Hooker_Gen_Variant_46 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Gen.Variant.Barys.459769.vir, Virus.Hooker_Gen.Variant.Barys.459769.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27fd98b8b7350784d8ea8186174b34a41fe14e65d0436417b90083406674631c"
    hash2       = "37202cb6dd087185df521f37e3ee2b44381a0b90bf1d2f8d4d0502badf5f3c30"

  strings:
    $s1  = "Analogous" fullword ascii
    $s2  = "animalistic" fullword ascii
    $s3  = "conceptualist" fullword ascii
    $s4  = "malapertness" fullword ascii
    $s5  = "Detachability" fullword ascii
    $s6  = "Absurdity" fullword ascii
    $s7  = "Hempseed" fullword ascii
    $s8  = "Benzoic" fullword ascii
    $s9  = "Abortiveness" fullword ascii
    $s10 = "Charitably" fullword ascii
    $s11 = "Discolor" fullword ascii
    $s12 = "Aperiodic" fullword ascii
    $s13 = "Columbic" fullword ascii
    $s14 = "Filching" fullword ascii
    $s15 = "Offhanded" fullword ascii
    $s16 = "Autogiro" fullword ascii
    $s17 = "Boorishness" fullword ascii
    $s18 = "calking" fullword ascii
    $s19 = "Burnie" fullword ascii
    $s20 = "Outhit" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c400e9d8592ae0a4e757a7b8e82b8c55" and (8 of them)
    ) or (all of them)
}