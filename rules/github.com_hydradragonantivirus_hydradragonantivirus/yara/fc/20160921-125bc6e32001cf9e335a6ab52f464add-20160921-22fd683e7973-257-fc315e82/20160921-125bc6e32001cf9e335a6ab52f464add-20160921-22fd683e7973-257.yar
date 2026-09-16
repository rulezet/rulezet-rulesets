rule _20160921_125bc6e32001cf9e335a6ab52f464add_20160921_22fd683e7973_257 {
  meta:
    description = "datamaliciousorder - from files 20160921_125bc6e32001cf9e335a6ab52f464add.js, 20160921_22fd683e7973fc938e9d6980e5e81789.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85fd75eaf5744358778610f756047b2dcd2017e11bf6f105849c49d56486df9c"
    hash2       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"

  strings:
    $s1  = "on fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s2  = "return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(" ascii
    $s3  = "k(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";" ascii
    $s4  = "Bg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s5  = ",(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii
    $s6  = "(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){re" ascii
    $s7  = "})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuc" ascii
    $s8  = "n fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s9  = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){" ascii
    $s10 = "),(function fuck(){return \"Nm\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Np\";})(),(function fuck(){" ascii
    $s11 = "Oe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s12 = "){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";" ascii
    $s13 = "ction fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s14 = "rn \"MBg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s15 = "eturn \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s16 = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return" ascii
    $s17 = "fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"U" ascii
    $s18 = "{return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";}" ascii
    $s19 = ")(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(" ascii
    $s20 = "ck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}