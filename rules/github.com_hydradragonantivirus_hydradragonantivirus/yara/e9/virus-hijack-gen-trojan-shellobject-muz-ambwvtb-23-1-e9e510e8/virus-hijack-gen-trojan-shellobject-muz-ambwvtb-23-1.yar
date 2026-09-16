rule Virus_Hijack_Gen_Trojan_ShellObject_MuZ_amBwvTb_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.MuZ@amBwvTb_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1736d604d6c8a14948ebe5386727ca3de215e1163904eac094b39769b8faea64"

  strings:
    $s1 = "(Chinhu-Chakasenderwa Service Message DLL" fullword ascii
    $s2 = "Chinhu-Chakasenderwa Service Message DLL" fullword wide
    $s3 = "\"Gogo1000 Was Here! Disc: gogo#3940" fullword ascii
    $s4 = "Gogo1000 Was Also Here" fullword ascii
    $s5 = "/Gogo1000 Was Also Here.xWyu 1#lEf`Hd6^eQJ{O kG>" fullword ascii
    $s6 = "\"Btw dont try to deobfuscate pls :(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}