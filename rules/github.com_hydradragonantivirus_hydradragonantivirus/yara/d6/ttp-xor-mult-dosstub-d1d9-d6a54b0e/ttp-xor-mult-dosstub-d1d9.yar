rule TTP_XOR_MULT_DOSStub_d1d9 {
  strings:
    $key_d1d9 = { 85 b1 [2] f1 a9 [2] b6 ab [2] f1 ba [2] bf b6 [2] b3 bc [2] a4 b7 [2] bf f9 [2] 82 }

  condition:
    any of them
}