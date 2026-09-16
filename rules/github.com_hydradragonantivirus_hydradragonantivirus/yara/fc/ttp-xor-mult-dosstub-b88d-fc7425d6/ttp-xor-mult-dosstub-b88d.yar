rule TTP_XOR_MULT_DOSStub_b88d {
  strings:
    $key_b88d = { ec e5 [2] 98 fd [2] df ff [2] 98 ee [2] d6 e2 [2] da e8 [2] cd e3 [2] d6 ad [2] eb }

  condition:
    any of them
}