rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_4951 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_c330005443bf481e5f5fac8acbb85145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash5       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"

  strings:
    $s1 = "\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function " ascii
    $s2 = "ction fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retu" ascii
    $s3 = " \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(func" ascii
    $s4 = " \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s5 = "n \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}