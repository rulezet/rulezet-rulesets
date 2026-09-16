rule TTP_XOR_MULT_DOSStub_a584 {
  strings:
    $key_a584 = { f1 ec [2] 85 f4 [2] c2 f6 [2] 85 e7 [2] cb eb [2] c7 e1 [2] d0 ea [2] cb a4 [2] f6 }

  condition:
    any of them
}