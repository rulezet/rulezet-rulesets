rule TTP_XOR_MULT_DOSStub_4ac2 {
  strings:
    $key_4ac2 = { 1e aa [2] 6a b2 [2] 2d b0 [2] 6a a1 [2] 24 ad [2] 28 a7 [2] 3f ac [2] 24 e2 [2] 19 }

  condition:
    any of them
}