rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_94_1_Virus_Hijac_471 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_94_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aSlVvue_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a8oUJio_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCeX4wn_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCeX4wn_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCXl7mh_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e14d1d158998f22959f211f9e2feea34726d5dc1de90bdbd949019849c03750"
    hash2       = "91d09b73a3f638010f734b8398243c4cdb0575c33622f5ae1376f8305cc14747"
    hash3       = "d844995b47ab1f9d1a95b909e382380afa062a1f0521122870999b6bbdc90d84"
    hash4       = "168aee83c044931b80edd5370772d034add50255d7fe6e7d147c0b799ae80586"
    hash5       = "d195727ae8b7fbd386d9bae2a4ec1adcc594dc8f886fe499e52cf4ce7dd102c6"
    hash6       = "1198fc5f2fd191d672b8f3be0150d8137076d3fed0ce00bba6dc072c172c8430"
    hash7       = "2e0eb3e7456f58807443b03fcc284e795a4b51f2122e4923a9f975d241ad7392"
    hash8       = "c344ea82aca503cb6e6d8b7ef462b80c7e5041de53e6720c1adf678c1d10e505"

  strings:
    $s1 = " (description \"" fullword ascii
    $s2 = "         (description \"" fullword ascii
    $s3 = "        (description \"" fullword ascii
    $s4 = "   (description \"" fullword ascii
    $s5 = "  (name \"" fullword ascii
    $s6 = " (name \"" fullword ascii
    $s7 = "  (label" fullword ascii
    $s8 = "  (label " fullword ascii
    $s9 = " (category " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}