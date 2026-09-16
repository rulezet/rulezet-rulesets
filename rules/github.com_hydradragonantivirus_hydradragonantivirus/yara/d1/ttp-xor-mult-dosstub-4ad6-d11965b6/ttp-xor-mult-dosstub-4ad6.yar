rule TTP_XOR_MULT_DOSStub_4ad6 {
  strings:
    $key_4ad6 = { 1e be [2] 6a a6 [2] 2d a4 [2] 6a b5 [2] 24 b9 [2] 28 b3 [2] 3f b8 [2] 24 f6 [2] 19 }

  condition:
    any of them
}