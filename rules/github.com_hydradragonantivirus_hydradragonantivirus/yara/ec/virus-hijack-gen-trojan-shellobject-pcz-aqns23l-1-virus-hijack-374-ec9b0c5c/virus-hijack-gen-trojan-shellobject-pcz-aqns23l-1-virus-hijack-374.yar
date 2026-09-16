import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_1_Virus_Hijack__374 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77abe2f3a6b18027499150b0a39df088beb927fc75fcc305e58d2826e4c79cf0"
    hash2       = "e8a37d168d3797d084b67a7aef5a87e673bbc7c10e4e7796c76f3a18f0554ebd"
    hash3       = "578e1cdc67f2bc90abded73fd735daba99c68d7d46edb63595852c38ead15073"
    hash4       = "99db69836c2554d1558a5a51d52a5e8019750166be376836a5967b7dab894872"

  strings:
    $s1 = "lable to able tsa" fullword ascii
    $s2 = "able tsal" fullword ascii
    $s3 = "Rare, tsa" fullword ascii
    $s4 = "ttsrpatcherp, to the field u" fullword ascii
    $s5 = "able t" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "824f061ba670840f601e752dee7095fd" and (all of them)
    ) or (all of them)
}