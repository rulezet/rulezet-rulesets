rule TTP_XOR_MULT_DOSStub_40d5 {
  strings:
    $key_40d5 = { 14 bd [2] 60 a5 [2] 27 a7 [2] 60 b6 [2] 2e ba [2] 22 b0 [2] 35 bb [2] 2e f5 [2] 13 }

  condition:
    any of them
}