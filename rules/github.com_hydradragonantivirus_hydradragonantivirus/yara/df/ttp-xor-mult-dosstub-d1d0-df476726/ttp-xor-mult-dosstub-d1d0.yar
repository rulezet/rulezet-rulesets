rule TTP_XOR_MULT_DOSStub_d1d0 {
  strings:
    $key_d1d0 = { 85 b8 [2] f1 a0 [2] b6 a2 [2] f1 b3 [2] bf bf [2] b3 b5 [2] a4 be [2] bf f0 [2] 82 }

  condition:
    any of them
}