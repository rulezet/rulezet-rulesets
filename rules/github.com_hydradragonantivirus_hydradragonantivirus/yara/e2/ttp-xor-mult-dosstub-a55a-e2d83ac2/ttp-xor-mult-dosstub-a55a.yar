rule TTP_XOR_MULT_DOSStub_a55a {
  strings:
    $key_a55a = { f1 32 [2] 85 2a [2] c2 28 [2] 85 39 [2] cb 35 [2] c7 3f [2] d0 34 [2] cb 7a [2] f6 }

  condition:
    any of them
}