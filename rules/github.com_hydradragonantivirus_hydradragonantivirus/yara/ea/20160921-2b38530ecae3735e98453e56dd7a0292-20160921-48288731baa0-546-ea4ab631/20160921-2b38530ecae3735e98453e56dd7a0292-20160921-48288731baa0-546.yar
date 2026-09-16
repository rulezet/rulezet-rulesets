rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_48288731baa0_546 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_48288731baa006b25b4e98b12520da2b.js, 20160921_de770f0ed114194a1a9d5e965c4fe675.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "ce917015afcf31459cc47b8864f85394a756701f6338f6a2cbe079779c3ecd43"
    hash3       = "57a3f4ba7362a09dfecfe27f6b8517c8290bc04a7020f4bbe4e9200a42655be0"

  strings:
    $s1  = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s2  = "k\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function" ascii
    $s3  = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"P" ascii
    $s4  = "ck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\"" ascii
    $s5  = "k(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";}" ascii
    $s6  = "uck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"US" ascii
    $s7  = ",(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii
    $s8  = "eturn \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(" ascii
    $s9  = " \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(funct" ascii
    $s10 = "function fuck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s11 = "k(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\"" ascii
    $s12 = "on fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"" ascii
    $s13 = "function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){re" ascii
    $s14 = "on fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s15 = "{return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(" ascii
    $s16 = "Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s17 = "(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"DAa\";" ascii
    $s18 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LG" ascii
    $s19 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retu" ascii
    $s20 = " \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}