rule _20160921_32a3b245a67cd982da1d38f57645b403_20160921_35613f26ab82_3611 {
  meta:
    description = "datamaliciousorder - from files 20160921_32a3b245a67cd982da1d38f57645b403.js, 20160921_35613f26ab8269650aa877fd5af3e43b.js, 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f7e53a243b56341e3d17450083c46ba2a33141b25134577db086128321a8223"
    hash2       = "432da9fcdf6c0d62e24e70562f7949325e57abff120248541ccbdaf091d0a7f3"
    hash3       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash4       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash5       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"

  strings:
    $s1 = "(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\"" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(funct" ascii
    $s3 = "eturn \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s4 = "uck(){return \"Qh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\"" ascii
    $s5 = "k(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj" ascii
    $s6 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}