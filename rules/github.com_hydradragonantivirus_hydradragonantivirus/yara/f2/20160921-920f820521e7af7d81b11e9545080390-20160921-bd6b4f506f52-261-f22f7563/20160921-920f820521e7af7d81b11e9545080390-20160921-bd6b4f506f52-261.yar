rule _20160921_920f820521e7af7d81b11e9545080390_20160921_bd6b4f506f52_261 {
  meta:
    description = "datamaliciousorder - from files 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1  = "uck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn" ascii
    $s2  = "eturn \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(" ascii
    $s3  = "ck(){return \"MBg\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs" ascii
    $s4  = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s5  = "Pu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(functio" ascii
    $s6  = "\"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(func" ascii
    $s7  = "return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s8  = "\"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(fun" ascii
    $s9  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return " ascii
    $s10 = "k(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\"" ascii
    $s11 = "(function fuck(){return \"ADy\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){" ascii
    $s12 = "turn \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})()," ascii
    $s13 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s14 = "){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";}" ascii
    $s15 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck()" ascii
    $s16 = " \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UXf\";})(),(fun" ascii
    $s17 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return " ascii
    $s18 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s19 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"V" ascii
    $s20 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}