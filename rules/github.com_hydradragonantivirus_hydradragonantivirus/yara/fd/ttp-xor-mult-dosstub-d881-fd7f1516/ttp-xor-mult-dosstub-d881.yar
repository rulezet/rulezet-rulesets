rule TTP_XOR_MULT_DOSStub_d881 {
  strings:
    $key_d881 = { 8c e9 [2] f8 f1 [2] bf f3 [2] f8 e2 [2] b6 ee [2] ba e4 [2] ad ef [2] b6 a1 [2] 8b }

  condition:
    any of them
}