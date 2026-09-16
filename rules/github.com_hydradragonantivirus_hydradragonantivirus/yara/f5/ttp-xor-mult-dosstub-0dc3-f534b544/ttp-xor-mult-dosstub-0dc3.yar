rule TTP_XOR_MULT_DOSStub_0dc3 {
  strings:
    $key_0dc3 = { 59 ab [2] 2d b3 [2] 6a b1 [2] 2d a0 [2] 63 ac [2] 6f a6 [2] 78 ad [2] 63 e3 [2] 5e }

  condition:
    any of them
}