rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_5e9244484429_4177 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_5e9244484429cd897ec88fe97140c29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"

  strings:
    $s1 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s2 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s3 = "on fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s4 = "{return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})" ascii
    $s5 = "unction fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}