rule TTP_XOR_MULT_DOSStub_a502 {
  strings:
    $key_a502 = { f1 6a [2] 85 72 [2] c2 70 [2] 85 61 [2] cb 6d [2] c7 67 [2] d0 6c [2] cb 22 [2] f6 }

  condition:
    any of them
}