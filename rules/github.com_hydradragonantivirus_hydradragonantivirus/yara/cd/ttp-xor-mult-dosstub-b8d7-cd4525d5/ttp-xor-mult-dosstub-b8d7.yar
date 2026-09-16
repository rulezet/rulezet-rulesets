rule TTP_XOR_MULT_DOSStub_b8d7 {
  strings:
    $key_b8d7 = { ec bf [2] 98 a7 [2] df a5 [2] 98 b4 [2] d6 b8 [2] da b2 [2] cd b9 [2] d6 f7 [2] eb }

  condition:
    any of them
}