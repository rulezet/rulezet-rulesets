rule _20160518_0156640fd3653d77f15c6f1429489761_20160518_57c9baff2d5a_1268 {
  meta:
    description = "datamaliciousorder - from files 20160518_0156640fd3653d77f15c6f1429489761.js, 20160518_57c9baff2d5abce3ebd45d7751d99b06.js, 20160518_65ce0c4c67cfdad0378ab86aefca381c.js, 20160518_84cb32b4183c4005fc04486699416395.js, 20160518_b773a4f49968da63c4c4eebdd2e31083.js, 20160518_e6af91f42e29ce01888f77732c4fcfef.js, 20160518_f9a82d1727ba0f05357c35cff1c785be.js, 20160519_ec64cc9dbc87894d1b64361011796fde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3dec3ff7d9a00e6d2dd7eb28c7cb27bbd73448d2162714fea35a55388884953"
    hash2       = "250a301b350629c8be5e7aaa73f1b19ea02efb12c2a12d34b2dd45f8a5091a63"
    hash3       = "5bccdaf5056352d90e75396ba93511a91fe34857521932ca8870165f96f67ee6"
    hash4       = "8b4bd3a37cde23aa0f1692b6264e8bb90860d28930929aac43d540a05ba0f39f"
    hash5       = "171e08d97da8aa6c6ec145a0032b017537cf0e45a3a33c89cd22aed87eaf525b"
    hash6       = "ed399c5c0c31239ee64ee6d090d3e2c45ec5cdd48216a009eb45359fd1a70220"
    hash7       = "1e3627a5fcf352031067d744215e2e6a6c4d869718328ca0560f928468202d22"
    hash8       = "132489f40cf884e75ddd004347768fa4f7ccc90d726d2ad74ed1ba619ae6770a"

  strings:
    $s1 = "solid1[CAD](getAttribute0 /* T  */, dingy, (true, false));" fullword ascii
    $s2 = "function sDiv2(){return newtonsCradle0 /* T  */;};" fullword ascii
    $s3 = "dot1 /* T  */= true;/* T  */" fullword ascii
    $s4 = "newtonsCradle1 /* T  */ = \"start \"+picker+\"\\r\\nexit\"" fullword ascii
    $s5 = "function doled(selectStart0){doled1[(\"3\", \"2\", \"R\")+ \"u\" + (\"1\", \"n\")](selectStart0, A8name /* T  */, A8name /* T  *" ascii

  condition:
    (uint16(0) == 0x6176 and (all of them)
    ) or (all of them)
}