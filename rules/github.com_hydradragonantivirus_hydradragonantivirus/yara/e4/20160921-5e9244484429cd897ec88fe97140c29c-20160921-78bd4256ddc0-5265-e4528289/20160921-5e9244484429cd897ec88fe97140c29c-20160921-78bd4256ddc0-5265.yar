rule _20160921_5e9244484429cd897ec88fe97140c29c_20160921_78bd4256ddc0_5265 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e9244484429cd897ec88fe97140c29c.js, 20160921_78bd4256ddc0b384791a12e8ab1fd8a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"
    hash2       = "c64d081235a424574ab6bbe64470cbee71a700f01b638afac6d0954ebc5cc0a0"

  strings:
    $s1 = "ck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"QTc\"" ascii
    $s2 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"QTc\"" ascii
    $s3 = "function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s4 = "(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){re" ascii
    $s5 = "XCr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}