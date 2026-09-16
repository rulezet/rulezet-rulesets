rule TTP_XOR_MULT_DOSStub_0bd0 {
  strings:
    $key_0bd0 = { 5f b8 [2] 2b a0 [2] 6c a2 [2] 2b b3 [2] 65 bf [2] 69 b5 [2] 7e be [2] 65 f0 [2] 58 }

  condition:
    any of them
}