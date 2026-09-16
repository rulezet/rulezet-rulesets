rule _20160921_18e4d81197d615e3008ec96ea25b7dc4_20160921_37277908f811_513 {
  meta:
    description = "datamaliciousorder - from files 20160921_18e4d81197d615e3008ec96ea25b7dc4.js, 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_68e1fc90afca497654d8f771197c2097.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b707313cf8ee2fdf903e5516937a17e48e75059c21a08483659705a96da9670"
    hash2       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash3       = "2dfe35f2d9bfd20a5e4771207c1627566795391c957d7b630cc669d3d8856ffd"
    hash4       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash5       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash6       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"
    hash7       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1  = "GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Kw\";})(),(function" ascii
    $s2  = "on f000(){return \"Qa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s3  = "00(){return \"Sq\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s4  = "eturn \"DYx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(" ascii
    $s5  = "ion f000(){return \"Br\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"" ascii
    $s6  = "{return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})" ascii
    $s7  = "function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s8  = "rn \"IAa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s9  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"UEg" ascii
    $s10 = ",(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s11 = "(){return \"HJm\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";" ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Oe" ascii
    $s13 = "n \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s14 = "ction f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){retu" ascii
    $s15 = "tion f000(){return \"MMz\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Um\";})(),(function f000(){return" ascii
    $s16 = ",(function f000(){return \"Kw\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s17 = "\"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s18 = "turn \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})()" ascii
    $s19 = "return \"ZGq\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s20 = "ction f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}