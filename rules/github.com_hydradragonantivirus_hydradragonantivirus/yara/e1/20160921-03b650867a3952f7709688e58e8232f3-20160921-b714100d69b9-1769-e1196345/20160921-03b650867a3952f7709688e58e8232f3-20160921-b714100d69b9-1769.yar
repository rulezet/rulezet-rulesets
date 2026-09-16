rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_b714100d69b9_1769 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"FJs\";})(),(functio" ascii
    $s2  = "fuck(){return \"Xw\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s3  = "{return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(" ascii
    $s4  = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5  = "ction fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s6  = "})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s7  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\";})(),(function fuck(" ascii
    $s8  = "ction fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s9  = " fuck(){return \"QTc\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s10 = "unction fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}