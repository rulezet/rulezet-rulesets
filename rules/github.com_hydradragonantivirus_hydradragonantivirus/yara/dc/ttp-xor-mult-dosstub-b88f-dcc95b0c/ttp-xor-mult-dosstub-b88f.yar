rule TTP_XOR_MULT_DOSStub_b88f {
  strings:
    $key_b88f = { ec e7 [2] 98 ff [2] df fd [2] 98 ec [2] d6 e0 [2] da ea [2] cd e1 [2] d6 af [2] eb }

  condition:
    any of them
}