rule TTP_XOR_MULT_DOSStub_1ac3 {
  strings:
    $key_1ac3 = { 4e ab [2] 3a b3 [2] 7d b1 [2] 3a a0 [2] 74 ac [2] 78 a6 [2] 6f ad [2] 74 e3 [2] 49 }

  condition:
    any of them
}