rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_627f79d589bd_616 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1  = " \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fun" ascii
    $s2  = "{return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s3  = "(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";" ascii
    $s4  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar" ascii
    $s5  = "Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6  = "Sf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(functio" ascii
    $s7  = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s8  = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){" ascii
    $s9  = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s10 = "{return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})" ascii
    $s11 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s12 = "fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IP" ascii
    $s13 = "n \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(fu" ascii
    $s14 = "turn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s15 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s16 = "rn \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(fun" ascii
    $s17 = "tion fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s18 = "){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s19 = "urn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s20 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Py" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}