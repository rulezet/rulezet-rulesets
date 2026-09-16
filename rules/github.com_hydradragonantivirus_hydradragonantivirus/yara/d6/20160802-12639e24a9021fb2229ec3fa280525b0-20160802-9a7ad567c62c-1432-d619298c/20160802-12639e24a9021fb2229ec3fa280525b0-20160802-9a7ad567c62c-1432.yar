rule _20160802_12639e24a9021fb2229ec3fa280525b0_20160802_9a7ad567c62c_1432 {
  meta:
    description = "datamaliciousorder - from files 20160802_12639e24a9021fb2229ec3fa280525b0.js, 20160802_9a7ad567c62cfaab314f58f47c245677.js, 20160802_d260e278228aa3b0f80a7ca9414d11fa.js, 20160802_d6369cf4eb0fa2af3ff95998fe381ad4.js, 20160802_ffe7284b443f60c6e6295e70bec04aa6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bb39f9014d2e60c94e825f147b955e29f9e186932dc6d4742ac340451f98382"
    hash2       = "a52d52ac269c791cb972b0f3596c667526105de45a2b67b875710fc5dd43b4a0"
    hash3       = "5adfbbce20af7f358c0fe286ac8292cc4ef378e577c1b97eba8c4ca63904ff23"
    hash4       = "459af0100c6ed3fe5a397861729391197c67151d558fb5f1f4eeec2dcdff0c50"
    hash5       = "58058ddbd1b7c0c9043f243907ef3b166caf5939bbc29063e08b0b1c02e0d547"

  strings:
    $s1 = "\\nvar Dr \\x3d \"Creat\" + \"\";\\r\\nvar ZFt = \"gth\" + \"\";\\r\\nv\\x61\\x72 B\\x768 = \"l\\x65n\" + \"\";\\r\\nfunction Zk" ascii
    $s2 = "e\" +\\x20\"\";\\r\\nvar J\\x57z\\x33 = \\x22n\" + \"\\x22;\\r\\x0av\\x61r APp7 = \"ope\" + \"\";\\r\\nf\\x75nction Xp6(Ik){retu" ascii
    $s3 = "75ncti\\x6fn STv0\\x28Ra0){return Ra0;};var T\\x56r3\\x20=\\x20\"e\" + \"\";\\r\\nvar \\x56Tk0 = \"\\x77rit\\x22 + \"\"\\x3b\\r" ascii
    $s4 = "x72eam\" + \"\";\\r\\nv\\x61r Yv \\x3d \"St\" + \"\\x22;\\r\\nvar \\x58Os = \"DB.\"\\x20+ \"\";\\r\\x0afu\\x6ection V\\x773(NAa)" ascii
    $s5 = "r\\x0av\\x61r Uh6 = \"len\" \\x2b \"\"\\x3b\\x0d\\nfuncti\\x6fn\\x20\\x4bEx3(TEw){return TEw;};var\\x20Aa9 = \"\\x47ET\" +\\x20" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}