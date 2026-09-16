rule TTP_XOR_MULT_DOSStub_a541 {
  strings:
    $key_a541 = { f1 29 [2] 85 31 [2] c2 33 [2] 85 22 [2] cb 2e [2] c7 24 [2] d0 2f [2] cb 61 [2] f6 }

  condition:
    any of them
}