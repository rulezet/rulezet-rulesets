rule TTP_XOR_MULT_DOSStub_7fc2 {
  strings:
    $key_7fc2 = { 2b aa [2] 5f b2 [2] 18 b0 [2] 5f a1 [2] 11 ad [2] 1d a7 [2] 0a ac [2] 11 e2 [2] 2c }

  condition:
    any of them
}