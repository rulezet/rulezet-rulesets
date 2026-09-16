rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_6ae4be616177_2854 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js, 20160921_8be5b3aac0a2f47acb168b56c6f880bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"
    hash3       = "344d7dd8865545f9f4c1045a85547b4140c66621aeedeb02bf60ff4598ff6930"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(fu" ascii
    $s2 = "(){return \"MUs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\"" ascii
    $s3 = "o\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s4 = "n \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5 = "function fuck(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s6 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"SU" ascii
    $s7 = "ion fuck(){return \"XCr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}