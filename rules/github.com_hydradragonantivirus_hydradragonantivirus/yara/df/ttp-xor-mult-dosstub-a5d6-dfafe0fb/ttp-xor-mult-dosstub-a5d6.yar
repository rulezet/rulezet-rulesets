rule TTP_XOR_MULT_DOSStub_a5d6 {
  strings:
    $key_a5d6 = { f1 be [2] 85 a6 [2] c2 a4 [2] 85 b5 [2] cb b9 [2] c7 b3 [2] d0 b8 [2] cb f6 [2] f6 }

  condition:
    any of them
}