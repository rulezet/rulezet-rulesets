rule _20160921_8be5b3aac0a2f47acb168b56c6f880bf_20160921_bc3224e9a637_3973 {
  meta:
    description = "datamaliciousorder - from files 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js, 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_df47c7f57f308287ca344dcc34150b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"
    hash2       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash3       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"

  strings:
    $s1 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){" ascii
    $s2 = " \"KVh\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})(),(fu" ascii
    $s3 = " fuck(){return \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ug" ascii
    $s4 = "),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s5 = "urn \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s6 = " fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}