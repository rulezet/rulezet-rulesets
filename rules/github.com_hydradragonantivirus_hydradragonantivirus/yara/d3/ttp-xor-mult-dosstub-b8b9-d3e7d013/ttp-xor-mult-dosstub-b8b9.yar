rule TTP_XOR_MULT_DOSStub_b8b9 {
  strings:
    $key_b8b9 = { ec d1 [2] 98 c9 [2] df cb [2] 98 da [2] d6 d6 [2] da dc [2] cd d7 [2] d6 99 [2] eb }

  condition:
    any of them
}