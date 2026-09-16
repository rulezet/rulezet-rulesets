rule TTP_XOR_MULT_DOSStub_d1a4 {
  strings:
    $key_d1a4 = { 85 cc [2] f1 d4 [2] b6 d6 [2] f1 c7 [2] bf cb [2] b3 c1 [2] a4 ca [2] bf 84 [2] 82 }

  condition:
    any of them
}