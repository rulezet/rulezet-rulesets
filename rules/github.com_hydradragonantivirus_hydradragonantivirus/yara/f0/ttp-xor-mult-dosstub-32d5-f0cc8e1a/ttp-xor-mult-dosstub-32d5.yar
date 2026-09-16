rule TTP_XOR_MULT_DOSStub_32d5 {
  strings:
    $key_32d5 = { 66 bd [2] 12 a5 [2] 55 a7 [2] 12 b6 [2] 5c ba [2] 50 b0 [2] 47 bb [2] 5c f5 [2] 61 }

  condition:
    any of them
}