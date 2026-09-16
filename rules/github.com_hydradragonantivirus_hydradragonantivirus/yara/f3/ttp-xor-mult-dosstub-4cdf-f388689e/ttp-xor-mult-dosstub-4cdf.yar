rule TTP_XOR_MULT_DOSStub_4cdf {
  strings:
    $key_4cdf = { 18 b7 [2] 6c af [2] 2b ad [2] 6c bc [2] 22 b0 [2] 2e ba [2] 39 b1 [2] 22 ff [2] 1f }

  condition:
    any of them
}