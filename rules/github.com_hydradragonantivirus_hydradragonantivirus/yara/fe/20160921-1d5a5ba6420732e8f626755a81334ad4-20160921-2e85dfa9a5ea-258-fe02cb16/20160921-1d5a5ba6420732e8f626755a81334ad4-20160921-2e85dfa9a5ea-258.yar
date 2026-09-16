rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_2e85dfa9a5ea_258 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_57d7efd4078096b801e379ee02f0feec.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_b04f9fe7316d0e86c0046e130e905e37.js, 20160921_cda776f6c5cb6eec510c00d5294fbfae.js, 20160921_e01bb59eb24d1686f9e2aeb1c9237853.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash3       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash4       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash5       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash6       = "e568760a55d343665c530313749711c3424bfd35c792b1a8b1d5ad6fa004c9a6"
    hash7       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash8       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash9       = "58df336ac7568c9f52fedec5d0b900480491f3e65f56c23426010ec745a6bddd"
    hash10      = "064df16cff12584bccc68fb79fe80908e6edeb4ccf32c3c0b6a79b8b0424820c"
    hash11      = "6f5c056ecbe8fe7bc86b4862d32e261ec2bc26cff4b18206988fdb1c7059557c"
    hash12      = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1  = "uck(){return \"IOs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s2  = "})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(" ascii
    $s3  = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"W" ascii
    $s4  = "n fuck(){return \"Xw\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg" ascii
    $s5  = "\"Dc\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(functi" ascii
    $s6  = " \"ZLd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s7  = "urn \"XCr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s8  = "turn \"Fv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s9  = "k(){return \"Xw\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})" ascii
    $s10 = "n \"Xw\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(funct" ascii
    $s11 = "return \"KVh\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s12 = "n \"Wo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s13 = "tion fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s14 = "(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Mw\";}" ascii
    $s15 = "),(function fuck(){return \"To\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){r" ascii
    $s16 = "){return \"Oh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";}" ascii
    $s17 = "on fuck(){return \"Xw\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"" ascii
    $s18 = " \"Xg\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(functi" ascii
    $s19 = "on fuck(){return \"Na\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s20 = "urn \"GWo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"IPu\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}