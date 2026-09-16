rule _20160921_5e9244484429cd897ec88fe97140c29c_20160921_af22e174703e_2993 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash2       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1 = "(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"XCr\";})(),(function fuck" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3 = "\"LGo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s4 = "function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s5 = "Bg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s6 = "uck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii
    $s7 = "urn \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}