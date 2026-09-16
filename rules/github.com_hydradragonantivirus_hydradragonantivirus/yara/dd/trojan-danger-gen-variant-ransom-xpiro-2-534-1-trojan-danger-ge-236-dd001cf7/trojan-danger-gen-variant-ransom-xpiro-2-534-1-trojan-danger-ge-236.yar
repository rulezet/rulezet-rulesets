import "pe"
rule _Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_534_1_Trojan_Danger_Ge_236 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_534_1.vir, Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_54_1.vir, Trojan.Danger_Trojan.GenericKD.72304918_209_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@amBwvTb.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@amBwvTb_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@amBwvTb_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@amBwvTb_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.xuZ@amBwvTb_4.vir, Virus.Hijack_Trojan.GenericKDZ.103285_195.vir, Virus.Hijack_Trojan.GenericKDZ.103285_279.vir, Virus.Hijack_Trojan.GenericKDZ.103285_380.vir, Virus.Hijack_Trojan.GenericKDZ.103285_461.vir, Virus.Hijack_Trojan.GenericKDZ.103285_797.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "468266dc6c596264a3540c37af95f1657dde82db50aa8f9c58170ab6d83719e2"
    hash2       = "67c0ac54eadf422679ee043281a6df1b089524d433e2bebe4a670101466678e9"
    hash3       = "2f8ef883ff67054203a5a698789ed47d83fd3a17630c5800ec0e6c7a44d05705"
    hash4       = "4ab1091f9071188635ca7c22adc178304fc6c76f5be0d6cd35946a31126c6230"
    hash5       = "489a7d4ac16e995dab90d4b3fce0358cbe1f39eb90b1e57178db4c1fe13a541c"
    hash6       = "5223d3893e361d63105a765ebcec6a155bdc87e8d1b1a88d4a9ad2fa0fd06e3c"
    hash7       = "e08b304903432599c0d26fe332b2b12055719e43652a707833d646e1afa12b5d"
    hash8       = "b36e330d5e0ef92bc67871b421fa01612c7f2ed3cacdc726876d90306045043e"
    hash9       = "d95f4c59308ac8c1a5cc4599c96fd00c91525f656508e0d044a39e096ae85b13"
    hash10      = "adb4d3cc1aa7bdb641950a313353f052c55b11c36d8f3a8e90646f6cf3422725"
    hash11      = "81aad9274782386791b61bcf0c07bf8c5fc2f4e5c524fc5664040ceb1bfe0843"
    hash12      = "3ae7de3d4b54267f3121998fc73503cf81e0897e14586ce423cc327f68db077a"
    hash13      = "82a6d384d3b2902838948e6ef180778d36c344ed949170e425a9ea0549a17414"

  strings:
    $s1 = "\\90, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 302790, 30" ascii
    $s2 = "hanges_per_iterations_': [], 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08" ascii
    $s3 = "Pse, 'minimization_result_': array([0.36453534, 0.01538238, 0.61398079, 0.06315343, 0.30427363," fullword ascii
    $s4 = "ec3d00>, 'is_debug': False, 'minimization_result_': array([0.36453534, 0.01538238, 0.61398079, 0.06315343, 0.30427363," fullword ascii
    $s5 = " 'model_wrapper': <secml_malware.attack.blackbox.c_wrapper_phi.CEnd2EndWrapperPhi object at 0x7f5c08ec3d00>, 'is_debug': False, " ascii
    $s6 = "'minimization_result_': array([0.36453534, 0.01538238, 0.61398079, 0.06315343, 0.30427363," fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (all of them)
    ) or (all of them)
}