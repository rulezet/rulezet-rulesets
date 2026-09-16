rule TTP_XOR_MULT_DOSStub_d1c5 {
  strings:
    $key_d1c5 = { 85 ad [2] f1 b5 [2] b6 b7 [2] f1 a6 [2] bf aa [2] b3 a0 [2] a4 ab [2] bf e5 [2] 82 }

  condition:
    any of them
}