rule TTP_XOR_MULT_DOSStub_b8c2 {
  strings:
    $key_b8c2 = { ec aa [2] 98 b2 [2] df b0 [2] 98 a1 [2] d6 ad [2] da a7 [2] cd ac [2] d6 e2 [2] eb }

  condition:
    any of them
}