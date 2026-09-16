rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_241_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_241_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fd125e9441872142c17928ec6070a9d48de9f51c127f9b5be6dfb5b94fcbc97"

  strings:
    $s1  = "%s:error:%s:%s:%s:%s:%d:%s" fullword ascii
    $s2  = "%s, Algorithm (%s), Properties (%s)" fullword ascii
    $s3  = "invalid key len" fullword ascii
    $s4  = "algorithm fetch failed" fullword ascii
    $s5  = "error creating kur" fullword ascii
    $s6  = "error creating cr" fullword ascii
    $s7  = "invalid keylen" fullword ascii
    $s8  = "Content-Disposition: attachment; filename=\"=?UTF-8?B?" fullword ascii
    $s9  = "error creating ir" fullword ascii
    $s10 = "HERE-->" fullword ascii
    $s11 = "checking pbm no secret available" fullword ascii
    $s12 = "error creating p10cr" fullword ascii
    $s13 = "invalid mode int" fullword ascii
    $s14 = "both mode and mode int" fullword ascii
    $s15 = "invalid taglen" fullword ascii
    $s16 = "invalid ivlen" fullword ascii
    $s17 = "derivation function mandatory for fips" fullword ascii
    $s18 = "inavlid ukm length" fullword ascii
    $s19 = "history " fullword wide
    $s20 = "unsupported alg for popsigningkey" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}