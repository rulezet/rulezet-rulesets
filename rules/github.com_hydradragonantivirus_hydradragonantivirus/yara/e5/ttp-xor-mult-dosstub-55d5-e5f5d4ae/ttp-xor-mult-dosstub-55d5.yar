rule TTP_XOR_MULT_DOSStub_55d5 {
  strings:
    $key_55d5 = { 01 bd [2] 75 a5 [2] 32 a7 [2] 75 b6 [2] 3b ba [2] 37 b0 [2] 20 bb [2] 3b f5 [2] 06 }

  condition:
    any of them
}