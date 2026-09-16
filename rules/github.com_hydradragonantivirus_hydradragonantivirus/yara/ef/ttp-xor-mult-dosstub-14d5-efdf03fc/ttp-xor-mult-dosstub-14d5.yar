rule TTP_XOR_MULT_DOSStub_14d5 {
  strings:
    $key_14d5 = { 40 bd [2] 34 a5 [2] 73 a7 [2] 34 b6 [2] 7a ba [2] 76 b0 [2] 61 bb [2] 7a f5 [2] 47 }

  condition:
    any of them
}