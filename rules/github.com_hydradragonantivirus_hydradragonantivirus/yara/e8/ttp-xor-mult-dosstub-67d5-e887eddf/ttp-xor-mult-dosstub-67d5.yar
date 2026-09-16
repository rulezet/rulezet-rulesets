rule TTP_XOR_MULT_DOSStub_67d5 {
  strings:
    $key_67d5 = { 33 bd [2] 47 a5 [2] 00 a7 [2] 47 b6 [2] 09 ba [2] 05 b0 [2] 12 bb [2] 09 f5 [2] 34 }

  condition:
    any of them
}