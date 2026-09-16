rule _20160921_30a55f1f397a54f31c6f0c59c99d921d_20160921_48b0ab2357d6_3594 {
  meta:
    description = "datamaliciousorder - from files 20160921_30a55f1f397a54f31c6f0c59c99d921d.js, 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_6ae4be616177cbd93c9c15ffb5dcddae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a24b75a2a7e52cbe65ddc3ad587a945b24afb617cb2d98581f0b06c49777984"
    hash2       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash3       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash4       = "4a4141c2adab0ebca262f25d7f6a45b773b074628a9522401e8dfa28d4889ccb"

  strings:
    $s1 = "k(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\"" ascii
    $s2 = "unction fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s3 = "function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){r" ascii
    $s4 = ")(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(function fuck" ascii
    $s5 = "\"XCr\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s6 = "return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Wo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}