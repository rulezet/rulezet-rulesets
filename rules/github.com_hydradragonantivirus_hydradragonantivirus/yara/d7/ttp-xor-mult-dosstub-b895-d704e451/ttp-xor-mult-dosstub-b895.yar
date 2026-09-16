rule TTP_XOR_MULT_DOSStub_b895 {
  strings:
    $key_b895 = { ec fd [2] 98 e5 [2] df e7 [2] 98 f6 [2] d6 fa [2] da f0 [2] cd fb [2] d6 b5 [2] eb }

  condition:
    any of them
}