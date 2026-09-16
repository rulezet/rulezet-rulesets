rule TTP_XOR_MULT_DOSStub_04d8 {
  strings:
    $key_04d8 = { 50 b0 [2] 24 a8 [2] 63 aa [2] 24 bb [2] 6a b7 [2] 66 bd [2] 71 b6 [2] 6a f8 [2] 57 }

  condition:
    any of them
}