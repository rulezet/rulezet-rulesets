import "pe"
rule _Trojan_Autorun__Dump_Generic_Dacic_19E38D3B_A_AAF775A0_2_Trojan_452 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun _Dump.Generic.Dacic.19E38D3B.A.AAF775A0_2.vir, Trojan.Autorun_1822.Trojan.Win32.VB.kph_2.vir, Trojan.Autorun_Backdoor.Hupigon.AAAH_1_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.18BF2EBF_1_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.18BF2EBF_2_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.18BF2EBF_4.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_10_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_11_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_12_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_13_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_14_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_1_2.vir, Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_90.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_272_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.e8X@aian2n_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08534277cbfb86840d5250f0a0672ac1fa61a3173cdbccaa2f14e0b9707527aa"
    hash2       = "506458aaeef61f70cf73da3d71d5452cd859cfd9fbcc7cf515d27265ace2421d"
    hash3       = "121f61ebfff0c27ee2a9df12e2d27e1908c8b895b7c80083be925498216d4c47"
    hash4       = "2416408f0c44630a0a34198b1f0cfcc39433230236cf8ab3e09ceba77a749467"
    hash5       = "51b54616de868dfaa1addcc28e0ca99f66a061de672858c2cdccafcce04aa335"
    hash6       = "7ad13f3353ceb15b4d751802829c239b0892f40ed4d56a1cda731ed44807f82a"
    hash7       = "bd757e2555712d97f1e557ceac39378bb7fa0e2f01492ebde67b07c56ea58925"
    hash8       = "d794df300789db006c10efb29a8cd2683c72070312700eff88f82e40c5548667"
    hash9       = "6fd5a741816876a01cba7faedbd4c98fc21243e49f46669d61506df36ebe78f4"
    hash10      = "8a54e41751369783c64f56f30133b985933092324e9b2dad025641d23643280c"
    hash11      = "50acb0d9a9bc6cbca94b77ff490d5aff20c453b24c1fdd498a38a0878755d0bd"
    hash12      = "25e5055023abbb8c18992618b6f04c94b8b13ff8bd33d4a4f8462d92902461bf"
    hash13      = "bec27130e133afdcfe5a436da5d210e96caadb8a922295caa36ac69a42d14fd9"
    hash14      = "74f29e0c765b24b3a34f3f430328fc58688ae0d8c7ef55297cd9d3b6dfeae8de"
    hash15      = "0269e12654cdeee23a263c2fa347dae7da354dad89e9b618e347f919813cf3f5"

  strings:
    $s1 = "Object is not a Temperature" fullword wide
    $s2 = "Player is being dealt a hand" fullword wide
    $s3 = "Game State Changed To: " fullword wide
    $s4 = "Arena de Batalha" fullword wide
    $s5 = "Your scores: " fullword wide
    $s6 = "Your score: " fullword wide
    $s7 = "Which cards would you like to switch? (press number key's)" fullword wide
    $s8 = "Press ESCAPE key to exit" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}