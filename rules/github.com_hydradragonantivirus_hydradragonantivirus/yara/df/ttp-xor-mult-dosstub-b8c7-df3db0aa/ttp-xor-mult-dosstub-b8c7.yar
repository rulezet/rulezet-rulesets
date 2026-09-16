rule TTP_XOR_MULT_DOSStub_b8c7 {
  strings:
    $key_b8c7 = { ec af [2] 98 b7 [2] df b5 [2] 98 a4 [2] d6 a8 [2] da a2 [2] cd a9 [2] d6 e7 [2] eb }

  condition:
    any of them
}