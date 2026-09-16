rule TTP_XOR_MULT_DOSStub_a585 {
  strings:
    $key_a585 = { f1 ed [2] 85 f5 [2] c2 f7 [2] 85 e6 [2] cb ea [2] c7 e0 [2] d0 eb [2] cb a5 [2] f6 }

  condition:
    any of them
}