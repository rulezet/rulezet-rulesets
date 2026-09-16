rule TTP_XOR_MULT_DOSStub_b892 {
  strings:
    $key_b892 = { ec fa [2] 98 e2 [2] df e0 [2] 98 f1 [2] d6 fd [2] da f7 [2] cd fc [2] d6 b2 [2] eb }

  condition:
    any of them
}