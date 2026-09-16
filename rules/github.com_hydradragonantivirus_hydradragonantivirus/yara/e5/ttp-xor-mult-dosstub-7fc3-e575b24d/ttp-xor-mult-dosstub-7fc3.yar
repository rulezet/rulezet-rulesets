rule TTP_XOR_MULT_DOSStub_7fc3 {
  strings:
    $key_7fc3 = { 2b ab [2] 5f b3 [2] 18 b1 [2] 5f a0 [2] 11 ac [2] 1d a6 [2] 0a ad [2] 11 e3 [2] 2c }

  condition:
    any of them
}