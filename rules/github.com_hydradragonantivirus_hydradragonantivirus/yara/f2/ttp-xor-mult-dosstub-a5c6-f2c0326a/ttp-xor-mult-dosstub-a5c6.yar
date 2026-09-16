rule TTP_XOR_MULT_DOSStub_a5c6 {
  strings:
    $key_a5c6 = { f1 ae [2] 85 b6 [2] c2 b4 [2] 85 a5 [2] cb a9 [2] c7 a3 [2] d0 a8 [2] cb e6 [2] f6 }

  condition:
    any of them
}