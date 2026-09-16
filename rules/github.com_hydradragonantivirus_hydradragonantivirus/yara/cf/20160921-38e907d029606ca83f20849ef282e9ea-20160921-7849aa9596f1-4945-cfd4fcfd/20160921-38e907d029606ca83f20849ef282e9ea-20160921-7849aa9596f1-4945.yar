rule _20160921_38e907d029606ca83f20849ef282e9ea_20160921_7849aa9596f1_4945 {
  meta:
    description = "datamaliciousorder - from files 20160921_38e907d029606ca83f20849ef282e9ea.js, 20160921_7849aa9596f1b90468a6e3049d3c7482.js, 20160921_a82451728dd7bfad408a4db2acb0fdc4.js, 20160921_c330005443bf481e5f5fac8acbb85145.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a7c94fb58ddb4d2f337bf953d69adaa2c112a46daf304e06dcfb7cf8ebb0b9d"
    hash2       = "3d31ab296868269e376de237639f2fc64156cbd269cfe7201c3752a4e9fa11df"
    hash3       = "cc029dbbbae3e50c3897c9dba3b4e8d6d1ac7ce9c394a88923879538b37740cd"
    hash4       = "48b88395d1349b5b2e0a815e59769a737e11cc9a098f2346b628ab4ae088b44a"
    hash5       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"

  strings:
    $s1 = "eturn \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(" ascii
    $s2 = "rn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"ZLd\";})(),(f" ascii
    $s3 = "g\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ik\";})(),(function f" ascii
    $s4 = "fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Za" ascii
    $s5 = "function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}