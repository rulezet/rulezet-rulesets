rule TTP_XOR_MULT_DOSStub_64d5 {
  strings:
    $key_64d5 = { 30 bd [2] 44 a5 [2] 03 a7 [2] 44 b6 [2] 0a ba [2] 06 b0 [2] 11 bb [2] 0a f5 [2] 37 }

  condition:
    any of them
}