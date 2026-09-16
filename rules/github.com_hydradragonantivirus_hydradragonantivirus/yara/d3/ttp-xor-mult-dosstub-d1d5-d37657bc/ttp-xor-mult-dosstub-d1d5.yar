rule TTP_XOR_MULT_DOSStub_d1d5 {
  strings:
    $key_d1d5 = { 85 bd [2] f1 a5 [2] b6 a7 [2] f1 b6 [2] bf ba [2] b3 b0 [2] a4 bb [2] bf f5 [2] 82 }

  condition:
    any of them
}