rule TTP_XOR_MULT_DOSStub_1bd1 {
  strings:
    $key_1bd1 = { 4f b9 [2] 3b a1 [2] 7c a3 [2] 3b b2 [2] 75 be [2] 79 b4 [2] 6e bf [2] 75 f1 [2] 48 }

  condition:
    any of them
}