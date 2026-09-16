rule TTP_XOR_MULT_DOSStub_a562 {
  strings:
    $key_a562 = { f1 0a [2] 85 12 [2] c2 10 [2] 85 01 [2] cb 0d [2] c7 07 [2] d0 0c [2] cb 42 [2] f6 }

  condition:
    any of them
}