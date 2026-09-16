rule _20160921_a210d5e93bf8b06dbd0a1b262abe210f_20160921_dc73cfa7a33e_620 {
  meta:
    description = "datamaliciousorder - from files 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"
    hash2       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"

  strings:
    $s1  = "(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s2  = "(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";" ascii
    $s3  = "(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s4  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s5  = " fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IP" ascii
    $s6  = "ck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm" ascii
    $s7  = "{return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";}" ascii
    $s8  = "turn \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s9  = "ction fuck(){return \"AUx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s10 = "ck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\"" ascii
    $s11 = "eturn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})()," ascii
    $s12 = "on fuck(){return \"Cd\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s13 = "(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(" ascii
    $s14 = "ction fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s15 = "(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck" ascii
    $s16 = "rn \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s17 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s18 = "\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function " ascii
    $s19 = "return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s20 = "n \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}