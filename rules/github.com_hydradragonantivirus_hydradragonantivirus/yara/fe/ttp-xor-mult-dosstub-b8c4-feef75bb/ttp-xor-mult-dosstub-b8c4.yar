rule TTP_XOR_MULT_DOSStub_b8c4 {
  strings:
    $key_b8c4 = { ec ac [2] 98 b4 [2] df b6 [2] 98 a7 [2] d6 ab [2] da a1 [2] cd aa [2] d6 e4 [2] eb }

  condition:
    any of them
}