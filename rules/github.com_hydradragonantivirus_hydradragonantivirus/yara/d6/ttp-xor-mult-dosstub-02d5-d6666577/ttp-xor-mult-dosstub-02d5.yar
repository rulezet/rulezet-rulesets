rule TTP_XOR_MULT_DOSStub_02d5 {
  strings:
    $key_02d5 = { 56 bd [2] 22 a5 [2] 65 a7 [2] 22 b6 [2] 6c ba [2] 60 b0 [2] 77 bb [2] 6c f5 [2] 51 }

  condition:
    any of them
}