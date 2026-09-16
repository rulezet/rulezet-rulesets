rule TTP_XOR_MULT_DOSStub_b8c1 {
  strings:
    $key_b8c1 = { ec a9 [2] 98 b1 [2] df b3 [2] 98 a2 [2] d6 ae [2] da a4 [2] cd af [2] d6 e1 [2] eb }

  condition:
    any of them
}