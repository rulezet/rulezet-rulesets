rule TTP_XOR_MULT_DOSStub_b8c6 {
  strings:
    $key_b8c6 = { ec ae [2] 98 b6 [2] df b4 [2] 98 a5 [2] d6 a9 [2] da a3 [2] cd a8 [2] d6 e6 [2] eb }

  condition:
    any of them
}