rule _Trojan_Autorun_Trojan_GenericKD_72869045_Virus_Hijack_Gen_Troja_84 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72869045.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.fyY@aOF3i8p_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g0W@a4@lcVd_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_2_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_3_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_5_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.p8W@aCNb4Uo_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b4d08c1939546a758d6fe9b1b5284dc628aff3fef3cb798a4e535143a008a56"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash5       = "70026ec3929b27d3b7979666f6269ba6d6c5691abe9c4eb63fd04989c348f0c1"
    hash6       = "6a3ecd6dd8f8099413faeda6715cf1be7c4fd9388a5e35e2084d7641fc143965"
    hash7       = "b2108dfb3889c739424c76cfab89967b106303bbb48527797663968a5fad0c9c"
    hash8       = "91108d07454bd8e212cc115ef1211832c7fcadce9bb9fbae1000811f0ccaad7b"
    hash9       = "6eca375518c871cbafa55bb8b3f323c5138a90fe23a2590be889548e4186ae0c"
    hash10      = "66d0faa4052007cff3969e3b850cf218a17f7cc2a1282c9c956e0402fcfc35e6"
    hash11      = "1300abe8989a2b3b5e1ab0102c4decd1bb1035a73bacbe2b00a064fb74207f7b"
    hash12      = "88161fa41e18f1d57a2848956c024bd4376d03ece61626be61b46da1c9cd0062"
    hash13      = "4a358cd38d34db61937690de1c080533535f35e44b7ccc50d5b07c5bc183a797"

  strings:
    $s1  = "Execute a command inside Cutter" fullword ascii
    $s2  = "Error occurred during crash dump creation." fullword ascii
    $s3  = "<html><head/><body style=\" font-family:'Cantarell'; font-size:9pt; font-weight:400; font-style:normal;\"><p><span style=\" font" ascii
    $s4  = "* Operating System: " fullword ascii
    $s5  = "Error attaching. No process selected!" fullword ascii
    $s6  = "Choose a directory to save the crash dump in" fullword ascii
    $s7  = "https://github.com/radareorg/cutter/issues/new?&body=**Environment information**" fullword ascii
    $s8  = "ze:10pt;\">Want to help us make Cutter even better?<br/>Visit our </span><a href=\"https://github.com/radareorg/cutter\"><span s" ascii
    $s9  = "</span><a href=\"https://twitter.com/r2gui\"><span style=\" font-family:'Noto Sans'; font-size:10pt; text-decoration: underline;" ascii
    $s10 = "If you encounter any problems or have suggestions, please submit an issue to https://github.com/radareorg/cutter/issues" fullword ascii
    $s11 = "</span><a href=\"https://twitter.com/r2gui\"><span style=\" font-family:'Noto Sans'; font-size:10pt; text-decoration: underline;" ascii
    $s12 = "Cutter received a signal it can't handle and will close.<br/>Would you like to create a crash dump for a bug report?" fullword ascii
    $s13 = "Write De\\Encoded Base64 string" fullword ascii
    $s14 = "Suspend the process" fullword ascii
    $s15 = "Graphviz PostScript (*.ps)" fullword ascii
    $s16 = "Unable to switch to the requested process." fullword ascii
    $s17 = "Processes with same name as currently open file:" fullword ascii
    $s18 = "* Cutter version: " fullword ascii
    $s19 = "Debugged process exited (" fullword ascii
    $s20 = "Detach from process" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}