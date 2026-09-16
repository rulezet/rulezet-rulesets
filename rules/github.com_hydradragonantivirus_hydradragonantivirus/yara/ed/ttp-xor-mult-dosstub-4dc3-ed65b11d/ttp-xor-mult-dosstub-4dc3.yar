rule TTP_XOR_MULT_DOSStub_4dc3 {
  strings:
    $key_4dc3 = { 19 ab [2] 6d b3 [2] 2a b1 [2] 6d a0 [2] 23 ac [2] 2f a6 [2] 38 ad [2] 23 e3 [2] 1e }

  condition:
    any of them
}