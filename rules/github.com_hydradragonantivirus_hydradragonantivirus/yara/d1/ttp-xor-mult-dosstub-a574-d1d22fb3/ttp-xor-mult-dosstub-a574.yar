rule TTP_XOR_MULT_DOSStub_a574 {
  strings:
    $key_a574 = { f1 1c [2] 85 04 [2] c2 06 [2] 85 17 [2] cb 1b [2] c7 11 [2] d0 1a [2] cb 54 [2] f6 }

  condition:
    any of them
}