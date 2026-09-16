rule _Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_104_1_Virus_Hija_100 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash2       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash3       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash4       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash5       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash6       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash7       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash8       = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash9       = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash10      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash11      = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash12      = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "CutterBindings.CutterCore.getHexdumpPreview(offset:unsigned long long,size:int)->QString" fullword ascii
    $s2  = "CutterBindings.AddressableItemContextMenu.setTarget(): not enough arguments" fullword ascii
    $s3  = "CutterBindings.AddressableItemContextMenu.setTarget(offset:unsigned long long,name:QString=QString())" fullword ascii
    $s4  = "CutterBindings.AddressableItemContextMenu.setHasTarget(hasTarget:bool)" fullword ascii
    $s5  = "CutterBindings.AddressableItemContextMenu.setTarget(): too many arguments" fullword ascii
    $s6  = "CutterBindings.AddressableItemContextMenu.setTarget(): got multiple values for keyword argument 'name'." fullword ascii
    $s7  = "CutterBindings.Configuration.isFirstExecution()->bool" fullword ascii
    $s8  = "CutterBindings.CutterCore.getConfigDescription(k:char*)->QString" fullword ascii
    $s9  = "CutterBindings.AddressableItemContextMenu(parent:PySide2.QtWidgets.QWidget,mainWindow:CutterBindings.MainWindow)" fullword ascii
    $s10 = "CutterBindings.CutterCore.getBreakpointsAddresses()->QList[unsigned long long]" fullword ascii
    $s11 = "CutterBindings.Configuration.getConfigBool(key:QString)->bool" fullword ascii
    $s12 = "CutterBindings.CutterCore.getStack(): got multiple values for keyword argument 'size'." fullword ascii
    $s13 = "CutterBindings.CutterCore.sdbGet(path:QString,key:QString)->QString" fullword ascii
    $s14 = "CutterBindings.CutterDockWidget.isVisibleToUser()->bool" fullword ascii
    $s15 = "CutterBindings.CutterCore.getRegisterRefs(): got multiple values for keyword argument 'depth'." fullword ascii
    $s16 = "CutterBindings.MainWindow.createShowInMenu(parent:PySide2.QtWidgets.QWidget,address:unsigned long long)->PySide2.QtWidgets.QMenu" ascii
    $s17 = "CutterBindings.CutterCore.getStack(): got multiple values for keyword argument 'depth'." fullword ascii
    $s18 = "Invalid return value for plugin metadata description, expected %s, got %s." fullword ascii
    $s19 = "CutterBindings.CutterCore.getRegisterRefs(): too many arguments" fullword ascii
    $s20 = "CutterBindings.Configuration.getOutputRedirectionEnabled()->bool" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}