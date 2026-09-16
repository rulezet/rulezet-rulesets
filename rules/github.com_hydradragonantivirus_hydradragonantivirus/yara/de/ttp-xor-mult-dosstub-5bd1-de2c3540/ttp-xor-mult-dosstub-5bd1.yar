rule TTP_XOR_MULT_DOSStub_5bd1 {
  strings:
    $key_5bd1 = { 0f b9 [2] 7b a1 [2] 3c a3 [2] 7b b2 [2] 35 be [2] 39 b4 [2] 2e bf [2] 35 f1 [2] 08 }

  condition:
    any of them
}