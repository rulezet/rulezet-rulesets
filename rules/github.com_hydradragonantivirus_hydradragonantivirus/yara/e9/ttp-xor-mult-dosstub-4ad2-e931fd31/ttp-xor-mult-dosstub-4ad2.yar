rule TTP_XOR_MULT_DOSStub_4ad2 {
  strings:
    $key_4ad2 = { 1e ba [2] 6a a2 [2] 2d a0 [2] 6a b1 [2] 24 bd [2] 28 b7 [2] 3f bc [2] 24 f2 [2] 19 }

  condition:
    any of them
}