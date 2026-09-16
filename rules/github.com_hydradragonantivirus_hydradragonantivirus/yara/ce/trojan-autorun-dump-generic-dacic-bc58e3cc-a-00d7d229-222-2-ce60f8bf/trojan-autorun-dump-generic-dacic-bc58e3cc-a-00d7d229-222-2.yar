rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_222_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_222_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "166c477928d3f10104edbb3a44e7922567c70a8bf58f51a76fa971fd2ad8194c"

  strings:
    $s1 = "(Chinhu-Chakasenderwa Service Message DLL" fullword ascii
    $s2 = "Chinhu-Chakasenderwa Service Message DLL" fullword wide
    $s3 = "0Gogo1000 Was Also Here.X0yDB_o{pL!j9x@6wmN2-tZ?!" fullword ascii
    $s4 = "\"Gogo1000 Was Here! Disc: gogo#3940" fullword ascii
    $s5 = "Gogo1000 Was Also Here" fullword ascii
    $s6 = ",c4j)SNOP" fullword ascii
    $s7 = "Diet*t" fullword ascii
    $s8 = "J)tEEM" fullword ascii
    $s9 = "\"Btw dont try to deobfuscate pls :(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}