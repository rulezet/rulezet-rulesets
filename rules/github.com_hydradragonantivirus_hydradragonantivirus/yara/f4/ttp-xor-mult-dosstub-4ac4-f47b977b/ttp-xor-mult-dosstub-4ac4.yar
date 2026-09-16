rule TTP_XOR_MULT_DOSStub_4ac4 {
  strings:
    $key_4ac4 = { 1e ac [2] 6a b4 [2] 2d b6 [2] 6a a7 [2] 24 ab [2] 28 a1 [2] 3f aa [2] 24 e4 [2] 19 }

  condition:
    any of them
}