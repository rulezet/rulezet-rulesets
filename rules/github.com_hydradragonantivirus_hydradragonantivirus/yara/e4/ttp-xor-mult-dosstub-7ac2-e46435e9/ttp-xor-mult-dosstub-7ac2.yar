rule TTP_XOR_MULT_DOSStub_7ac2 {
  strings:
    $key_7ac2 = { 2e aa [2] 5a b2 [2] 1d b0 [2] 5a a1 [2] 14 ad [2] 18 a7 [2] 0f ac [2] 14 e2 [2] 29 }

  condition:
    any of them
}