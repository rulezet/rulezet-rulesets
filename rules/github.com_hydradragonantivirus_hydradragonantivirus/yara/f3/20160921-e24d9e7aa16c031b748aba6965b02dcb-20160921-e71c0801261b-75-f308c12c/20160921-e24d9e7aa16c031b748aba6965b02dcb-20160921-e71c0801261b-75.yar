rule _20160921_e24d9e7aa16c031b748aba6965b02dcb_20160921_e71c0801261b_75 {
  meta:
    description = "datamaliciousorder - from files 20160921_e24d9e7aa16c031b748aba6965b02dcb.js, 20160921_e71c0801261b54c695ea1dac03e838bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c005836c702d4e1615fb302fc6f799ca097db41daa5b8cf6a66e8874a454d65b"
    hash2       = "c36b557af1bcfc43e39bfaabcd74048c39fc37b5ac0e9561b161a6d3d2e54e76"

  strings:
    $s1  = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s2  = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s3  = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(f" ascii
    $s4  = "unction fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s5  = "on fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s6  = " \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(fun" ascii
    $s7  = "uck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"DRx" ascii
    $s8  = "k(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";" ascii
    $s9  = " fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"N" ascii
    $s10 = ",(function fuck(){return \"Ve\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){" ascii
    $s11 = "eturn \"DAa\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()" ascii
    $s12 = "\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xw\";})(),(function fu" ascii
    $s13 = "rn \"MIl\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s14 = "Pu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function" ascii
    $s15 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){retur" ascii
    $s16 = "tion fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s17 = " \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s18 = " \"YQt\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s19 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(" ascii
    $s20 = "function fuck(){return \"Py\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}