rule TTP_XOR_MULT_DOSStub_a540 {
  strings:
    $key_a540 = { f1 28 [2] 85 30 [2] c2 32 [2] 85 23 [2] cb 2f [2] c7 25 [2] d0 2e [2] cb 60 [2] f6 }

  condition:
    any of them
}