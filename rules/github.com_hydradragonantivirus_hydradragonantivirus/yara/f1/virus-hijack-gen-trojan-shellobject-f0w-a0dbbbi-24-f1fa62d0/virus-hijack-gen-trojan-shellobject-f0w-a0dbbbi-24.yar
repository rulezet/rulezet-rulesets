rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_24 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_24.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db36003bea612ca2fc4aaf7776115e3d561641cf547b5cc280ce33f5add7f016"

  strings:
    $s1  = "--- ouPdisk space" fullword ascii
    $s2  = "ferred too many scanlines" fullword ascii
    $s3  = "e: width=%u, height" fullword ascii
    $s4  = "this imple" fullword ascii
    $s5  = "most likel" fullword ascii
    $s6  = "lowed here" fullword ascii
    $s7  = "{tart Of Scan:T" fullword ascii
    $s8  = "[] closure" fullword ascii
    $s9  = "Adobe color" fullword ascii
    $s10 = "Define Res" fullword ascii
    $s11 = "ogus DQT inde" fullword ascii
    $s12 = "+%`dynamic N" fullword ascii
    $s13 = "ming YCbCr" fullword ascii
    $s14 = "ffman code#p" fullword ascii
    $s15 = "Buffer pa" fullword ascii
    $s16 = " data: found " fullword ascii
    $s17 = "Virtual array controller m" fullword ascii
    $s18 = "rted with nonstandard sampl'-" fullword ascii
    $s19 = "id SOS parameters for sequential" fullword ascii
    $s20 = "ng: unknown JFIF revis" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}