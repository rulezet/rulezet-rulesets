rule TTP_XOR_MULT_DOSStub_a5a6 {
  strings:
    $key_a5a6 = { f1 ce [2] 85 d6 [2] c2 d4 [2] 85 c5 [2] cb c9 [2] c7 c3 [2] d0 c8 [2] cb 86 [2] f6 }

  condition:
    any of them
}