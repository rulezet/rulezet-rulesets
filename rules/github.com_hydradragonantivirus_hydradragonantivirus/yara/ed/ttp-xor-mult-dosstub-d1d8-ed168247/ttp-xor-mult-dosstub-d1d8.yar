rule TTP_XOR_MULT_DOSStub_d1d8 {
  strings:
    $key_d1d8 = { 85 b0 [2] f1 a8 [2] b6 aa [2] f1 bb [2] bf b7 [2] b3 bd [2] a4 b6 [2] bf f8 [2] 82 }

  condition:
    any of them
}