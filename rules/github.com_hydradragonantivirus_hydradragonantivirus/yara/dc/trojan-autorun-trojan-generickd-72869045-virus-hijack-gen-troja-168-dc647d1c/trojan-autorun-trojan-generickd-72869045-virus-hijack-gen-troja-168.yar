rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_168 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash3       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash4       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash5       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash6       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash7       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash8       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash9       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash10      = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash11      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash12      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash13      = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash14      = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "Save the target binary inside the project directory (prj.files)" fullword ascii
    $s2  = "Theme Editor - <%1>" fullword ascii
    $s3  = "Choose an offset and refresh to get decompiled code" fullword ascii
    $s4  = "Project is a git repo and saving is committing (prj.git)" fullword ascii
    $s5  = "Initialization Script" fullword ascii
    $s6  = "!!! Settings are not writable! Make sure you have a write access to \"%1\"" fullword ascii
    $s7  = "Wrong address" fullword ascii
    $s8  = "Use information provided by decompiler when highlighting code." fullword ascii
    $s9  = "Export Transparent Bitmap Graphs" fullword ascii
    $s10 = "Copy instruction address (%1)" fullword ascii
    $s11 = "Use simple project saving style (prj.simple, recommended)" fullword ascii
    $s12 = "Use ZIP format for project files (prj.zip)" fullword ascii
    $s13 = "Color theme <b>%1</b> was successfully exported." fullword ascii
    $s14 = "Theme named %1 already exists." fullword ascii
    $s15 = "Copy address of [flag] (<address>)" fullword ascii
    $s16 = "No function found at this offset. Seek to a function or define one in order to decompile it." fullword ascii
    $s17 = "Color theme <b>%1</b> was successfully imported." fullword ascii
    $s18 = "No Decompiler available." fullword ascii
    $s19 = "Type flag name or address here" fullword ascii
    $s20 = "Copy address of %1 (%2)" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}