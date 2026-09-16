rule TTP_XOR_MULT_DOSStub_d180 {
  strings:
    $key_d180 = { 85 e8 [2] f1 f0 [2] b6 f2 [2] f1 e3 [2] bf ef [2] b3 e5 [2] a4 ee [2] bf a0 [2] 82 }

  condition:
    any of them
}