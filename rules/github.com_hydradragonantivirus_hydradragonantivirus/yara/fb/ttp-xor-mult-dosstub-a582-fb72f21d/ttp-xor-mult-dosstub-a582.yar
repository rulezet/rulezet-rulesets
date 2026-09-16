rule TTP_XOR_MULT_DOSStub_a582 {
  strings:
    $key_a582 = { f1 ea [2] 85 f2 [2] c2 f0 [2] 85 e1 [2] cb ed [2] c7 e7 [2] d0 ec [2] cb a2 [2] f6 }

  condition:
    any of them
}