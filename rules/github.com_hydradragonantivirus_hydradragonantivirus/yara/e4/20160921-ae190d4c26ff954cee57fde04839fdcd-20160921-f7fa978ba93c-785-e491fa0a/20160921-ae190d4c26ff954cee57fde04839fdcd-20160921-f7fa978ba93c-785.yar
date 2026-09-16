rule _20160921_ae190d4c26ff954cee57fde04839fdcd_20160921_f7fa978ba93c_785 {
  meta:
    description = "datamaliciousorder - from files 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1  = "){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";" ascii
    $s2  = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){retur" ascii
    $s3  = "ction fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retur" ascii
    $s4  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"P" ascii
    $s5  = ";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"PDf\";})(),(function fu" ascii
    $s6  = "uck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo" ascii
    $s7  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s8  = "turn \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s9  = "){return \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";" ascii
    $s10 = "return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})()" ascii
    $s11 = "uck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Wo0" ascii
    $s12 = "(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){re" ascii
    $s13 = "ck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu" ascii
    $s14 = "on fuck(){return \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s15 = "),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Et\";})(),(function fuck()" ascii
    $s16 = "SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(functi" ascii
    $s17 = "return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s18 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s19 = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})" ascii
    $s20 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}