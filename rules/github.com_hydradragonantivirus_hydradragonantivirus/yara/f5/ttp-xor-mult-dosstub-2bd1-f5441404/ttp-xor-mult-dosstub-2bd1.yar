rule TTP_XOR_MULT_DOSStub_2bd1 {
  strings:
    $key_2bd1 = { 7f b9 [2] 0b a1 [2] 4c a3 [2] 0b b2 [2] 45 be [2] 49 b4 [2] 5e bf [2] 45 f1 [2] 78 }

  condition:
    any of them
}