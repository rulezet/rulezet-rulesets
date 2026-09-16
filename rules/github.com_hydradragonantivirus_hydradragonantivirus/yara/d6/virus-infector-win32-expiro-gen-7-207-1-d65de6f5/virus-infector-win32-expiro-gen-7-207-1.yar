rule Virus_Infector_Win32_Expiro_Gen_7_207_1 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f28d31e0d2f566b324b081ef0c427a79fd48fb3fb50bfda0b8471bffa9969908"

  strings:
    $s1  = ".Copyright 2015 The Rubik Project AuthorsRubikRegular2.000;UKWN;Rubik-RegularRubik RegularVersion 2.000Rubik-RegularHubert & Fis" ascii
    $s2  = "LCopyright 2015 The Rubik Project AuthorsRubikRegular2.000;UKWN;Rubik-RegularRubik RegularVersion 2.000Rubik-RegularHubert & Fis" wide
    $s3  = "cherHubert and Fischerhttp://www.google.com/fontshttp://www.hubertfischer.comThis Font Software is licensed under the SIL Open F" ascii
    $s4  = "ont License, Version 1.1. This license is available with a FAQ at: http://scripts.sil.org/OFLhttp://scripts.sil.org/OFL" fullword ascii
    $s5  = "float4 PS(VS_OUTPUT input) : SV_TARGET" fullword ascii
    $s6  = "C7])#######hV0qs'/###[),##/l:$#Q6>##5[n42>c-TH`->>#/e>11NNV=Bv(*:.F?uu#(gRU.o0XGH`$vhLG1hxt9?W`#,5LsCp#-i>.r$<$6pD>Lb';9Crc6tgXm" ascii
    $s7  = ".Copyright 2015 The Rubik Project AuthorsRubikRegular2.000;UKWN;Rubik-RegularRubik RegularVersion 2.000Rubik-RegularHubert & Fis" ascii
    $s8  = "Xtreaming Technology Inc.0" fullword ascii
    $s9  = "Xtreaming Technology Inc.1>0<" fullword ascii
    $s10 = "Airdrop" fullword ascii
    $s11 = "> Important Guns" fullword ascii
    $s12 = "Fast Run" fullword ascii
    $s13 = "float4 Color : COLOR;" fullword ascii
    $s14 = "L<head" fullword ascii
    $s15 = "Minibus" fullword ascii
    $s16 = "Vehicle Text Color" fullword ascii
    $s17 = "normalext size" fullword ascii
    $s18 = "Scooter" fullword ascii
    $s19 = "Same Colors" fullword ascii
    $s20 = "AirDrop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}