rule _20160921_469953d9833167e141d9f086f1f41437_20160921_bd6b4f506f52_1000 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1  = "turn \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s2  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retur" ascii
    $s3  = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XFd\";})" ascii
    $s4  = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){ret" ascii
    $s5  = "\"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s6  = "g\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s7  = "s\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s8  = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"AUx\";})()" ascii
    $s9  = "){return \"Ve\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s10 = "k(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";" ascii
    $s11 = "tion fuck(){return \"KVh\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s12 = "(function fuck(){return \"Av\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s13 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf" ascii
    $s14 = "})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s15 = "IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(funct" ascii
    $s16 = "){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";}" ascii
    $s17 = "tion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retur" ascii
    $s18 = "turn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})()," ascii
    $s19 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}