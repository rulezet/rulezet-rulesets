rule _20160921_3e1e1d6341df1caf923e4b9f79ea9ac3_20160921_468b13a80ecc_927 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e1e1d6341df1caf923e4b9f79ea9ac3.js, 20160921_468b13a80ecc75cd21428202c521ca1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d858d56d343b97488263af92c96b6bee8f8213dd2aec4d79132b57f04ea3c568"
    hash2       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"

  strings:
    $s1  = "Zy\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s2  = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retu" ascii
    $s3  = "return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s4  = "on fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s5  = "(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";" ascii
    $s6  = "(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){re" ascii
    $s7  = "on fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return " ascii
    $s8  = "(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";}" ascii
    $s9  = "ction fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s10 = "){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\";})" ascii
    $s11 = "rn \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s12 = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return" ascii
    $s13 = "fuck(){return \"Za\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\"" ascii
    $s14 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuc" ascii
    $s15 = "uck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu" ascii
    $s16 = "(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Dc\";})(),(function fuck()" ascii
    $s17 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return" ascii
    $s18 = "})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s19 = "{return \"Ve\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})()" ascii
    $s20 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}