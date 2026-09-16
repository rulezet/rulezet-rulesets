rule TTP_XOR_MULT_DOSStub_a583 {
  strings:
    $key_a583 = { f1 eb [2] 85 f3 [2] c2 f1 [2] 85 e0 [2] cb ec [2] c7 e6 [2] d0 ed [2] cb a3 [2] f6 }

  condition:
    any of them
}