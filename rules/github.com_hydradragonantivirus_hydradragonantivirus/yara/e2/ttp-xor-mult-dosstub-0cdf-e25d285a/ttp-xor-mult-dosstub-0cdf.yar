rule TTP_XOR_MULT_DOSStub_0cdf {
  strings:
    $key_0cdf = { 58 b7 [2] 2c af [2] 6b ad [2] 2c bc [2] 62 b0 [2] 6e ba [2] 79 b1 [2] 62 ff [2] 5f }

  condition:
    any of them
}