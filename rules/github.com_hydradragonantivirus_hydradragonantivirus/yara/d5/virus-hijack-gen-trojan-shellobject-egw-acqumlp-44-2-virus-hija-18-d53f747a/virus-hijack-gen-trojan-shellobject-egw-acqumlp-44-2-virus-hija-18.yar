import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_44_2_Virus_Hija_18 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_44_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_45_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_46_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_27.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26ceb2088e3c0c7e544f1c651fda4e8c72dc01be0a3e3cdf2a96a910adddfa4e"
    hash2       = "64fb452e2ddd537c723da1c3da985ec714926682cff1ffe7ff145eac58df9da0"
    hash3       = "fd9e0a02a8f78fc632627af72c5d008f84a2cede74f59e671edbbcb8912ffaa4"
    hash4       = "870a93359c479df4c40c056a5b504f28ee6153a44bc6026adc713909eb0002d6"
    hash5       = "7e284788b1ef7d117ac8ad337a1fb0a07dd12cd805057f6c09babd74148dffd2"
    hash6       = "3c311c23ee83e585f89f9c093c0031df6cddcf4d32396c9f42cbadc8e4d6c665"
    hash7       = "f7d2291661596daaebefab97d8fed04a28c1eca931738fd0dc163800ce05ebca"
    hash8       = "6035ff118fa9f279fea8e130f61b619912aa36803d65bcbc08b02a994aad3577"
    hash9       = "ba85313f1cdf0f595cfec4fc303ab6512cfed807b99d0e9bc87cd03430b7e602"
    hash10      = "33db8585f624b1a6addf136e2766f282888517f191919cc7f447ec8a12c30dff"
    hash11      = "d6ce20e4a58e386164d14b39baf6e2f88c27e180790bb796b4720194bc3aacbe"
    hash12      = "88a1ff243e7cafd54ac1a7c402cc2a3c505d916207bfe03be6834e8abbb394b2"
    hash13      = "87260bc44c75689f9bcf2a292151c13d58ffbe8d859a00ad180bdf7f84cf63e9"

  strings:
    $s1 = "1 -n 5 & Start " fullword ascii
    $s2 = " * FROM" fullword ascii
    $s3 = "Tool>lp" fullword ascii
    $s4 = "#BOUNDARY#\"" fullword ascii
    $s5 = "$aHUM$qH" fullword ascii
    $s6 = "echo Y|" fullword ascii
    $s7 = "  \"auto" fullword ascii
    $s8 = ".@REDO" fullword ascii
    $s9 = "HUGE PA" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c36e955e761e5107fcb7c1c91bb44606" and (all of them)
    ) or (all of them)
}