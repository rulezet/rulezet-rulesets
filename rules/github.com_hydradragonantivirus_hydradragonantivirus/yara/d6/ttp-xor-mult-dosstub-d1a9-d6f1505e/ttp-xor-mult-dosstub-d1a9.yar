rule TTP_XOR_MULT_DOSStub_d1a9 {
  strings:
    $key_d1a9 = { 85 c1 [2] f1 d9 [2] b6 db [2] f1 ca [2] bf c6 [2] b3 cc [2] a4 c7 [2] bf 89 [2] 82 }

  condition:
    any of them
}