rule TTP_XOR_MULT_DOSStub_a5c3 {
  strings:
    $key_a5c3 = { f1 ab [2] 85 b3 [2] c2 b1 [2] 85 a0 [2] cb ac [2] c7 a6 [2] d0 ad [2] cb e3 [2] f6 }

  condition:
    any of them
}