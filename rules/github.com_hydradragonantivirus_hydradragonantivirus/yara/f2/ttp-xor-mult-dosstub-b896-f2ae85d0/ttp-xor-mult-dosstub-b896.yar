rule TTP_XOR_MULT_DOSStub_b896 {
  strings:
    $key_b896 = { ec fe [2] 98 e6 [2] df e4 [2] 98 f5 [2] d6 f9 [2] da f3 [2] cd f8 [2] d6 b6 [2] eb }

  condition:
    any of them
}