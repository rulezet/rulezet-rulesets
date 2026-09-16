rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_b2419a000449_1512 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"

  strings:
    $s1  = "{return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s2  = " \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Zy\";})(),(func" ascii
    $s3  = "Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"CCb\";})(),(function" ascii
    $s4  = "function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii
    $s5  = "{return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})()," ascii
    $s6  = "return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s7  = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s8  = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){" ascii
    $s9  = "ck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii
    $s10 = "(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s11 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na\";})(),(function fuck(){retur" ascii
    $s12 = "fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s13 = "fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"UX" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}