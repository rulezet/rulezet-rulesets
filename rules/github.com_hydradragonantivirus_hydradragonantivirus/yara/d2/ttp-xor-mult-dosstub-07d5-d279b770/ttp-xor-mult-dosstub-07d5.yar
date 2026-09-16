rule TTP_XOR_MULT_DOSStub_07d5 {
  strings:
    $key_07d5 = { 53 bd [2] 27 a5 [2] 60 a7 [2] 27 b6 [2] 69 ba [2] 65 b0 [2] 72 bb [2] 69 f5 [2] 54 }

  condition:
    any of them
}