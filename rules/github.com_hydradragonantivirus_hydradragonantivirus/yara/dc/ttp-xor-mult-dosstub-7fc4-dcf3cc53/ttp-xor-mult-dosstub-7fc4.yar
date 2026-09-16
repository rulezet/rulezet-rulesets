rule TTP_XOR_MULT_DOSStub_7fc4 {
  strings:
    $key_7fc4 = { 2b ac [2] 5f b4 [2] 18 b6 [2] 5f a7 [2] 11 ab [2] 1d a1 [2] 0a aa [2] 11 e4 [2] 2c }

  condition:
    any of them
}