rule TTP_XOR_MULT_DOSStub_1bd0 {
  strings:
    $key_1bd0 = { 4f b8 [2] 3b a0 [2] 7c a2 [2] 3b b3 [2] 75 bf [2] 79 b5 [2] 6e be [2] 75 f0 [2] 48 }

  condition:
    any of them
}