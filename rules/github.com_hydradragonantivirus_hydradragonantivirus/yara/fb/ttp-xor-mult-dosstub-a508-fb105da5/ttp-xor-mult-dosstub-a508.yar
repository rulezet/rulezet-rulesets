rule TTP_XOR_MULT_DOSStub_a508 {
  strings:
    $key_a508 = { f1 60 [2] 85 78 [2] c2 7a [2] 85 6b [2] cb 67 [2] c7 6d [2] d0 66 [2] cb 28 [2] f6 }

  condition:
    any of them
}